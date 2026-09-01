#!/usr/bin/env bash
# Exact, non-vacuous Phase 285 witness conformance selector runner.
set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

PHASE285_WITNESS_TEMP_DIR=""
PHASE285_COMPLETE_RECEIPT_BOUND_DEVICE=""
PHASE285_COMPLETE_RECEIPT_BOUND_INODE=""
PHASE285_RELEASE_PROBE_RECEIPT_ROOT=""
PHASE285_RELEASE_PROBE_RECEIPT_TOKEN=""
PHASE285_RELEASE_PROBE_RECEIPT_SHA=""
cleanup_temp_dir() {
  if [ -n "$PHASE285_WITNESS_TEMP_DIR" ]; then
    local target="$PHASE285_WITNESS_TEMP_DIR"
    if [ -n "$PHASE285_COMPLETE_RECEIPT_BOUND_DEVICE" ] || [ -n "$PHASE285_COMPLETE_RECEIPT_BOUND_INODE" ]; then
      local observed_metadata observed_identity
      observed_metadata="$(phase285_directory_metadata "$target" 2>/dev/null)" || {
        echo "Phase 285 scratch bound inode is absent: $target" >&2
        return 1
      }
      observed_identity="${observed_metadata#*:}"
      [ "$observed_identity" = "$PHASE285_COMPLETE_RECEIPT_BOUND_DEVICE:$PHASE285_COMPLETE_RECEIPT_BOUND_INODE" ] || {
        echo "Phase 285 scratch bound inode was replaced: $target" >&2
        return 1
      }
      PHASE285_COMPLETE_RECEIPT_BOUND_DEVICE=""
      PHASE285_COMPLETE_RECEIPT_BOUND_INODE=""
    fi
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

phase285_directory_metadata() {
  python3 -I - "$1" <<'PY'
import os
import pathlib
import stat
import sys

path = pathlib.Path(sys.argv[1])
metadata = os.lstat(path)
if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
    raise SystemExit("PHASE285-DIRECTORY-METADATA[type]")
stable = os.stat(path, follow_symlinks=False)
identity = (metadata.st_dev, metadata.st_ino, metadata.st_mode)
if identity != (stable.st_dev, stable.st_ino, stable.st_mode):
    raise SystemExit("PHASE285-DIRECTORY-METADATA[unstable]")
print(f"{stat.S_IMODE(metadata.st_mode):o}:{metadata.st_dev}:{metadata.st_ino}")
PY
}

cleanup_temp_dir_on_exit() {
  local exit_code=$?
  cleanup_temp_dir || exit_code=1
  trap - EXIT
  exit "$exit_code"
}

complete_receipt_cleanup_on_exit() {
  local exit_code=$?
  trap - EXIT HUP INT TERM
  cleanup_temp_dir || exit_code=1
  exit "$exit_code"
}

complete_receipt_cleanup_on_signal() {
  local requested_signal="$1"
  trap - EXIT HUP INT TERM
  cleanup_temp_dir || exit 1
  trap - "$requested_signal"
  kill -s "$requested_signal" "$$"
  exit 1
}

complete_receipt_arm_cleanup_traps() {
  trap complete_receipt_cleanup_on_exit EXIT
  trap 'complete_receipt_cleanup_on_signal HUP' HUP
  trap 'complete_receipt_cleanup_on_signal INT' INT
  trap 'complete_receipt_cleanup_on_signal TERM' TERM
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
def within(child, ancestor):
    try:
        child.relative_to(ancestor)
        return True
    except ValueError:
        return False

if any(parent == boundary or within(parent, boundary) for boundary in boundaries):
    raise SystemExit("PHASE285-SCRATCH[parent-overlap]")

scratch = pathlib.Path(tempfile.mkdtemp(prefix=f"{prefix}.", dir=parent)).resolve(strict=True)
if any(scratch.iterdir()):
    shutil.rmtree(scratch)
    if scratch.exists():
        raise SystemExit("PHASE285-SCRATCH[nonempty-cleanup-failed]")
    raise SystemExit("PHASE285-SCRATCH[nonempty-new-directory]")

if any(within(scratch, boundary) or within(boundary, scratch) for boundary in boundaries):
    scratch.rmdir()
    if scratch.exists():
        raise SystemExit("PHASE285-SCRATCH[boundary-cleanup-failed]")
    raise SystemExit("PHASE285-SCRATCH[boundary-overlap]")
print(scratch)
PY
}

phase285_boundary_child_inventory() {
  python3 -I - "$1" <<'PY'
import base64
import os
import pathlib
import sys

boundary = pathlib.Path(sys.argv[1]).resolve(strict=True)
names = sorted(os.fsencode(entry.name) for entry in os.scandir(boundary))
encoded = b"".join(len(name).to_bytes(8, "big") + name for name in names)
print(base64.b64encode(encoded).decode("ascii"))
PY
}

phase285_scratch_hostile_controls() {
  local site="$1" boundary output exit_code before_children after_children rejected=0
  local boundaries=(
    "$ROOT_DIR"
    "$(git rev-parse --path-format=absolute --git-dir)"
    "$(git rev-parse --path-format=absolute --git-common-dir)"
  )
  for boundary in "${boundaries[@]}"; do
    before_children="$(phase285_boundary_child_inventory "$boundary")"
    exit_code=0
    output="$(TMPDIR="$boundary" phase285_create_confined_scratch "$site-hostile" 2>&1)" || exit_code=$?
    after_children="$(phase285_boundary_child_inventory "$boundary")"
    [ "$exit_code" -ne 0 ] && [ "$output" = "PHASE285-SCRATCH[parent-overlap]" ] || {
      echo "Phase 285 hostile TMPDIR was not refused: site=$site boundary=$boundary output=$output" >&2
      return 1
    }
    [ "$before_children" = "$after_children" ] || {
      echo "Phase 285 hostile TMPDIR refusal created a child path: site=$site boundary=$boundary" >&2
      return 1
    }
    rejected=$((rejected + 1))
  done
  echo "phase285_scratch_self_test site=$site boundaries=$rejected child_paths_created=0 passed=1"
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
client_failure_decoder_is_request_bound_without_raw_store_proof
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
service_request_draft_derives_nonce_operation_target_and_authorization_once
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
production_initializer_creates_reopens_and_reproduces_ready
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
        case "$case_name" in
          jetstream_cas_rejects_wrong_revision_header_or_ack|jetstream_cas_confirms_raw_sequence_and_bytes|jetstream_cas_rejects_del_purge_rollup_and_direct_reads|jetstream_checkpoint_*|full_service_path_rejects_runtime_private_subject_and_store_raw_api|full_service_path_rejects_credential_account_and_mount_swaps|full_service_path_validates_proxy_response_before_public_attestation|full_service_path_fails_closed_on_store_queue_exhaustion|production_initializer_creates_reopens_and_reproduces_ready)
            command="cargo test -p $package --test $target --locked --offline -- --ignored $case_name --exact"
            ;;
          *)
            command="cargo test -p $package --test $target --locked --offline -- $case_name --exact"
            ;;
        esac
      fi
      printf '%s\t%s\t%s\t%s\t%s\n' \
        "$selector" "$package" "$target" "$command" "$case_name"
    done < <(selector_rows "$selector")
  done < <(selectors)
}

# Each target has an independent exact inventory. The shared governance target
# remains frozen at twenty-two cases; the JetStream CAS target owns exactly five.
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
      printf '%s\n' full_service_path_constructor_deadline_is_exact_and_receipt_bound
      ;;
    *) return 1 ;;
  esac
}

REGISTRY_SHA256="92ee9b244594a569f7cb84897d230b629ab29e83918af4c58464623dda3b093f"
REGISTRY_ROW_COUNT=61

registry_validator() {
  local registry_file="$1" mode="${2:-validate}" selector="${3:-}"
  python3 -I - "$registry_file" "$REGISTRY_SHA256" "$REGISTRY_ROW_COUNT" "$mode" "$selector" <<'PY'
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

run_core_selector_self_tests() {
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

standalone_self_test_modes() {
  cat <<'EOF'
core-selector-registry
store-proxy-source
service-checkpoint-observation-source
transport-semantics-source
transport-semantics-registry
jetstream-release-hook
jetstream-iterator-source
transport-positive-readiness-parser
EOF
}

validate_aggregate_self_test_registry() {
  python3 -I - <<'PY'
import copy

expected = [
    "core-selector-registry",
    "store-proxy-source",
    "service-checkpoint-observation-source",
    "transport-semantics-source",
    "transport-semantics-registry",
    "jetstream-release-hook",
    "jetstream-iterator-source",
    "transport-positive-readiness-parser",
]

def validate(rows):
    if rows != expected:
        raise ValueError("aggregate_self_test_registry")
    if len(rows) != len(set(rows)):
        raise ValueError("aggregate_self_test_duplicate")

validate(expected)
mutations = []
mutations.append(("omission", expected[:-1]))
mutations.append(("addition", [*expected, "foreign-mode"]))
mutations.append(("duplication", [*expected, expected[-1]]))
substitution = copy.copy(expected)
substitution[3] = "transport-semantics-source-substring"
mutations.append(("substitution", substitution))
mutations.append(("zero", []))
for label, rows in mutations:
    try:
        validate(rows)
    except ValueError:
        print(f"aggregate_self_test_registry_mutation_red mutation={label}")
    else:
        raise SystemExit(f"aggregate self-test registry mutant survived: {label}")
print(f"aggregate_self_test_registry modes={len(expected)} mutations={len(mutations)} passed=1")
PY
}

phase285_portable_directory_metadata_self_test() {
  local scratch metadata mode device inode
  scratch="$(phase285_create_confined_scratch phase285-directory-metadata)"
  PHASE285_WITNESS_TEMP_DIR="$scratch"
  trap cleanup_temp_dir_on_exit EXIT
  metadata="$(phase285_directory_metadata "$scratch")"
  IFS=: read -r mode device inode <<<"$metadata"
  [ "$mode" = 700 ] && [[ "$device" =~ ^[0-9]+$ ]] && [[ "$inode" =~ ^[0-9]+$ ]] || {
    echo "Phase 285 portable directory metadata differs: $metadata" >&2
    return 1
  }
  python3 -I - "$ROOT_DIR/tools/check-phase285-witness-conformance.sh" <<'PY'
import pathlib
import sys

source = pathlib.Path(sys.argv[1]).read_text()
for token in ("st" + "at -f", "st" + "at -c", "st" + "at --format"):
    if token in source:
        raise SystemExit(f"portable directory metadata source guard found CLI token: {token}")
PY
  cleanup_temp_dir
  trap - EXIT
  echo "phase285_directory_metadata_self_test mode=700 identity=stable cli_stat_flags=0 passed=1"
}

run_self_tests() {
  validate_aggregate_self_test_registry
  phase285_portable_directory_metadata_self_test
  relay_recreation_canonical_route_guard self-test
  local count=0 mode
  while IFS= read -r mode; do
    [ -n "$mode" ] || continue
    case "$mode" in
      core-selector-registry)
        run_core_selector_self_tests
        ;;
      store-proxy-source)
        store_proxy_source_guard normal
        store_proxy_source_guard self-test
        ;;
      service-checkpoint-observation-source)
        observation_source_guard normal
        observation_source_guard self-test
        ;;
      transport-semantics-source)
        transport_semantics_source_guard normal
        transport_semantics_source_guard self-test
        ;;
      transport-semantics-registry)
        transport_semantics_registry_guard
        ;;
      jetstream-release-hook)
        run_release_hook_self_test
        ;;
      jetstream-iterator-source)
        checkpoint_iterator_source_guard \
          "$ROOT_DIR/crates/swarm-governance-witness/src/jetstream_store.rs" self-test
        ;;
      transport-positive-readiness-parser)
        transport_positive_readiness_parser_self_test
        ;;
      *)
        echo "unknown aggregate self-test mode: $mode" >&2
        return 1
        ;;
    esac
    count=$((count + 1))
  done < <(standalone_self_test_modes)
  [ "$count" -eq 8 ] || {
    echo "aggregate self-test execution count differs: executed=$count expected=8" >&2
    return 1
  }
  echo "aggregate_self_test modes=$count unique=8 executed_once=1 passed=1"
}

service_process_safety_source_guard() {
  python3 -I - "$ROOT_DIR/crates/swarm-governance-witness/src/runtime_client.rs" \
    "$ROOT_DIR/crates/swarm-governance-witness/src/public_dispatcher.rs" \
    "$ROOT_DIR/crates/swarm-governance-witness/src/store_proxy_service.rs" "${1:-normal}" <<'PY'
import hashlib,pathlib,sys
runtime_path,public_path,private_path=map(pathlib.Path,sys.argv[1:4]); mode=sys.argv[4]
source={"runtime":runtime_path.read_text(),"public":public_path.read_text(),"private":private_path.read_text()}
required=[
 ("sigint","runtime","SignalKind::interrupt()"),
 ("sigterm","runtime","SignalKind::terminate()"),
 ("typed_abnormal_exit","runtime","WitnessProcessErrorV1::AbnormalExit"),
 ("public_failure_select","runtime","_ = runner.wait_for_failure() => true,"),
 ("public_supervised_start","runtime","PublicWitnessServiceRunner::start_supervised("),
 ("raw_lifecycle_supervision","runtime","_ = &mut raw_failure => true,"),
 ("cancellation_safe_failure_wait","runtime","select_all(tasks.iter_mut()).await"),
 ("strict_owned_join","runtime","cancel_and_join_owned_tasks("),
 ("repeated_signal_stop","runtime","complete_single_stop_while_observing_signals("),
 ("public_stop","public","pub async fn stop_and_wait("),
 ("public_idempotent","public","if let Some(result) = self.stop_result"),
 ("public_await","public","cancel_and_join_owned_tasks(&mut self.tasks).await"),
 ("public_drain","public","client\n                        .drain()"),
 ("public_lifecycle","public","service_event_is_terminal(&event)"),
 ("private_stop","private","pub async fn stop_and_wait("),
 ("private_idempotent","private","if let Some(result) = self.stop_result"),
 ("private_await","private","cancel_and_join_owned_tasks(&mut self.tasks).await"),
 ("private_drain","private","client\n                        .drain()"),
 ("private_lifecycle","private","service_event_is_terminal(&event)"),
]
def validate(value):
 process_region=value["runtime"].split("pub async fn run_public_witness_process(",1)[1].split("pub struct RuntimeWitnessClient",1)[0]
 if "std::future::pending" in process_region: raise ValueError("pending_forever")
 if "mem::take(tasks)" in value["runtime"] or "mem::take(&mut self.tasks)" in value["public"] or "mem::take(&mut self.tasks)" in value["private"]: raise ValueError("detached_handles")
 for label,name,fragment in required:
  if fragment not in value[name]: raise ValueError(label)
 if value["runtime"].count("Err(WitnessProcessErrorV1::AbnormalExit)")!=3: raise ValueError("typed_abnormal_exit")
 if value["runtime"].count("_ = runner.wait_for_failure() => true,")!=2: raise ValueError("public_failure_select")
 for name in ("public","private"):
  stop=value[name].split("pub async fn stop_and_wait(",1)[1].split("\n    }\n}",1)[0]
  if not stop.index("self.ready.store(false") < stop.index("cancel_and_join_owned_tasks(&mut self.tasks).await") < stop.index(".drain()"):
   raise ValueError(name+"_shutdown_order")
validate(source)
if mode=="self-test":
 mutations=[
  ("pending_forever","runtime","if let Ok(token) = std::env::var(\"PHASE285_RELAY_TOPOLOGY_TOKEN\")","std::future::pending::<()>().await;\n    if let Ok(token) = std::env::var(\"PHASE285_RELAY_TOPOLOGY_TOKEN\")"),
  ("missing_sigterm","runtime","SignalKind::terminate()","SignalKind::interrupt()"),
  ("successful_error_exit","runtime","Err(WitnessProcessErrorV1::AbnormalExit)","Ok(())"),
  ("detached_public_runner","runtime","_ = runner.wait_for_failure() => true,","_ = signals.next() => false,"),
  ("ignored_raw_lifecycle","runtime","_ = &mut raw_failure => true,","_ = signals.next() => false,"),
  ("detached_wait_handles","runtime","select_all(tasks.iter_mut()).await","select_all(std::mem::take(tasks)).await"),
  ("public_abort_without_await","public","cancel_and_join_owned_tasks(&mut self.tasks).await","Ok(())"),
  ("public_drain_omitted","public","client\n                        .drain()","client\n                        .flush()"),
  ("public_lifecycle_ignored","public","service_event_is_terminal(&event)","false"),
  ("private_abort_without_await","private","cancel_and_join_owned_tasks(&mut self.tasks).await","Ok(())"),
  ("private_drain_omitted","private","client\n                        .drain()","client\n                        .flush()"),
  ("private_lifecycle_ignored","private","service_event_is_terminal(&event)","false"),
 ]
 digests=[]
 for label,name,old,new in mutations:
  if source[name].count(old)<1: raise SystemExit(f"process safety mutation anchor differs: {label}")
  candidate=dict(source); candidate[name]=candidate[name].replace(old,new,1)
  digests.append(hashlib.sha256(candidate[name].encode()).hexdigest())
  try: validate(candidate)
  except ValueError: print(f"service_process_safety_mutation_red mutation={label}")
  else: raise SystemExit(f"process safety mutant survived: {label}")
 if len(set(digests))!=len(mutations): raise SystemExit("process safety mutation digest reuse")
 print(f"service_process_safety_source mutations={len(mutations)} unique={len(set(digests))} passed=1")
else: print("service_process_safety_source passed=1")
PY
}

service_operational_bounds_source_guard() {
  python3 -I - "$ROOT_DIR/crates/swarm-governance-witness/src/service_config.rs" "${1:-normal}" <<'PY'
import hashlib,pathlib,sys
source=pathlib.Path(sys.argv[1]).read_text(); mode=sys.argv[2]
required=[
 ("worker_ceiling","pub const MAX_SERVICE_WORKERS: usize = 64;"),
 ("channel_ceiling","pub const MAX_SERVICE_CHANNEL_ENTRIES: usize = 1_024;"),
 ("aggregate_ceiling","pub const MAX_SERVICE_BUFFERED_BYTES: usize = 512 * 1024 * 1024;"),
 ("request_checked_add","max_request_bytes\n        .checked_add(BUFFER_FRAME_OVERHEAD_BYTES)"),
 ("response_checked_add","max_response_bytes\n        .checked_add(BUFFER_FRAME_OVERHEAD_BYTES)"),
 ("checked_multiply","worker_count.checked_mul("),
 ("checked_aggregate","total\n            .checked_add("),
 ("aggregate_rejection","if total > MAX_SERVICE_BUFFERED_BYTES"),
]
def validate(text):
 for label,fragment in required:
  if text.count(fragment)!=1: raise ValueError(label)
 if text.count("checked_service_buffer_budget(")<5: raise ValueError("budget_callsites")
validate(source)
if mode=="self-test":
 mutations=[
  (label,fragment,fragment.replace("64","65",1) if label=="worker_ceiling" else fragment.replace("1_024","1_025",1) if label=="channel_ceiling" else fragment.replace("512","513",1) if label=="aggregate_ceiling" else fragment.replace("checked_","saturating_",1) if "checked_" in fragment else fragment.replace(">",">=",1))
  for label,fragment in required
 ]
 digests=[]
 for label,old,new in mutations:
  candidate=source.replace(old,new,1); digests.append(hashlib.sha256(candidate.encode()).hexdigest())
  try: validate(candidate)
  except ValueError: print(f"service_operational_bounds_mutation_red mutation={label}")
  else: raise SystemExit(f"operational bounds mutant survived: {label}")
 if len(set(digests))!=len(mutations): raise SystemExit("operational bounds mutation digest reuse")
 print(f"service_operational_bounds_source mutations={len(mutations)} unique={len(set(digests))} passed=1")
else: print("service_operational_bounds_source passed=1")
PY
}

service_secret_files_source_guard() {
  python3 -I - "$ROOT_DIR/crates/swarm-governance-witness/src/secure_file.rs" \
    "$ROOT_DIR/crates/swarm-governance-witness/src/runtime_client.rs" \
    "$ROOT_DIR/crates/swarm-governance-witness/src/store_proxy_service.rs" \
    "$ROOT_DIR/crates/swarm-governance-witness/src/bin/swarm-governance-witness.rs" \
    "$ROOT_DIR/crates/swarm-governance-witness/src/bin/swarm-governance-witness-store.rs" \
    "$ROOT_DIR/crates/swarm-governance-witness/Cargo.toml" "${1:-normal}" <<'PY'
import hashlib,pathlib,sys
names=["secure","runtime","private","public_bin","private_bin","cargo"]
source=dict(zip(names,(pathlib.Path(path).read_text() for path in sys.argv[1:7]))); mode=sys.argv[7]
required=[
 ("nofollow","secure","OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC"),
 ("regular","secure","FileType::from_raw_mode(metadata.st_mode) != FileType::RegularFile"),
 ("single_link","secure","metadata.st_nlink != 1"),
 ("effective_uid","secure","rustix::process::geteuid().as_raw()"),
 ("closed_mode","secure","metadata.st_mode as u32 & PRIVATE_MODE_MASK"),
 ("bounded_read","secure",".checked_add(1)"),
 ("bounded_take","secure",".take(limit)"),
 ("stable_open","secure","same_identity(&before, &opened)"),
 ("post_read_fstat","secure","let after_read = fstat(&file)"),
 ("stable_final","secure","!same_identity(&opened, &after_reopened_read)"),
 ("stable_content","secure","bytes.as_slice() != reopened.as_slice()"),
 ("ctime_identity","secure","left.st_ctime == right.st_ctime"),
 ("zeroizing_bytes","secure","Zeroizing<Vec<u8>>"),
 ("runtime_zeroize","runtime","Zeroize, ZeroizeOnDrop"),
 ("canonical_zeroize","runtime","let canonical = Zeroizing::new("),
 ("utf8_without_byte_clone","runtime","std::str::from_utf8(bytes.as_slice())"),
 ("private_zeroize","private","Zeroize, ZeroizeOnDrop"),
 ("public_config_loader","public_bin","load_public_witness_process_config(path)?"),
 ("private_config_loader","private_bin","load_store_proxy_process_config(path)?"),
 ("rustix_dependency","cargo","rustix = { version = \"1\", features = [\"fs\", \"process\"] }"),
 ("zeroize_dependency","cargo","zeroize.workspace = true"),
]
def validate(value):
 for label,name,fragment in required:
  if fragment not in value[name]: raise ValueError(label)
 if value["secure"].count("OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC")!=2: raise ValueError("nofollow")
 if value["secure"].count(".take(limit)")!=2: raise ValueError("bounded_take")
 for name in ("runtime","private"):
  if "tokio::fs::read(" in value[name] or "tokio::fs::read_to_string(" in value[name]: raise ValueError(name+"_direct_read")
 if "secret_bytes.to_vec()" in value["runtime"]: raise ValueError("unzeroized_secret_copy")
 for name in ("public_bin","private_bin"):
  if "std::fs::read(" in value[name]: raise ValueError(name+"_direct_read")
 if value["runtime"].count("validate_stable_public_file(")<2 or value["private"].count("validate_stable_public_file(")<1: raise ValueError("stable_ca_reads")
 if value["runtime"].count("let canonical = Zeroizing::new(")!=3 or value["private"].count("let canonical = Zeroizing::new(")!=1: raise ValueError("canonical_zeroize")
validate(source)
if mode=="self-test":
 mutations=[
  ("follow_symlink","secure","OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC","OFlags::RDONLY"),
  ("accept_hardlink","secure","metadata.st_nlink != 1","false"),
  ("accept_foreign_owner","secure","metadata.st_uid != rustix::process::geteuid().as_raw()","false"),
  ("accept_wide_mode","secure","(metadata.st_mode as u32 & PRIVATE_MODE_MASK) != 0","false"),
  ("omit_post_read_fstat","secure","let after_read = fstat(&file)","let after_read = opened"),
  ("omit_ctime_identity","secure","left.st_ctime == right.st_ctime","true"),
  ("omit_final_identity","secure","!same_identity(&opened, &after_reopened_read)","false"),
  ("unwrapped_canonical","runtime","let canonical = Zeroizing::new(","let canonical = identity("),
  ("unbounded_read","secure",".take(limit)",".take(u64::MAX)"),
  ("public_direct_config_read","public_bin","load_public_witness_process_config(path)?","serde_json::from_slice(&std::fs::read(path)?)?"),
  ("private_direct_config_read","private_bin","load_store_proxy_process_config(path)?","serde_json::from_slice(&std::fs::read(path)?)?"),
 ]
 digests=[]
 for label,name,old,new in mutations:
  if source[name].count(old)<1: raise SystemExit(f"secret file mutation anchor differs: {label}")
  candidate=dict(source); candidate[name]=candidate[name].replace(old,new,1)
  digests.append(hashlib.sha256(candidate[name].encode()).hexdigest())
  try: validate(candidate)
  except ValueError: print(f"service_secret_files_mutation_red mutation={label}")
  else: raise SystemExit(f"secret file mutant survived: {label}")
 if len(set(digests))!=len(mutations): raise SystemExit("secret file mutation digest reuse")
 print(f"service_secret_files_source mutations={len(mutations)} unique={len(set(digests))} passed=1")
else: print("service_secret_files_source passed=1")
PY
}

run_service_process_safety_focus() {
  service_process_safety_source_guard normal
  service_process_safety_source_guard self-test
  cargo test -p swarm-governance-witness --lib --locked --offline \
    runtime_client::service_lifecycle_unit_tests -- --nocapture
}

run_service_operational_bounds_focus() {
  service_operational_bounds_source_guard normal
  service_operational_bounds_source_guard self-test
  cargo test -p swarm-governance-witness --lib --locked --offline \
    service_config::operational_bound_tests::operational_counts_and_aggregate_budget_are_closed -- --exact
}

run_service_secret_files_focus() {
  service_secret_files_source_guard normal
  service_secret_files_source_guard self-test
  cargo test -p swarm-governance-witness --lib --locked --offline secure_file::tests -- --nocapture
  cargo test -p swarm-governance-witness --lib --locked --offline \
    runtime_client::service_lifecycle_unit_tests::signing_secret_utf8_conversion_never_creates_an_unwrapped_byte_copy -- --exact
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
        "let payload = message.payload.to_vec();",
        "if !try_enqueue_public_message(ingress, ingress_message)",
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
        ("PublicWitnessDispatchErrorV1::OutcomeUnknown", 12),
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
        r"let response = self\.proxy\.compare_and_swap\(request\)\.await;(.*?)let response = match response \{(.*?)\n        \};(.*?)\n    async fn confirm_proposed",
        text,
        re.S,
    )
    if post_cas is None:
        raise ValueError("post-CAS classifier absent")
    classifier = post_cas.group(0)
    if classifier.count("self.proxy.compare_and_swap(") != 1:
        raise ValueError("post-CAS classifier retries compare-and-swap")
    transport_error = re.search(r"Err\(error\) => \{(.*?)\n            \}", post_cas.group(2), re.S)
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
    ("runner_queue_bypassed", "if !try_enqueue_public_message(ingress, ingress_message)", "if false"),
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
    runner_match = re.search(
        r"impl<S: WitnessAtomicStore \+ 'static> StoreProxyServiceRunner<S> \{(.*?)\n\}\n\npub\(crate\) fn admit_private_subscription_message",
        s,
        re.S,
    )
    if runner_match is None:
        raise ValueError("store_proxy_runner_impl")
    runner = runner_match.group(1)
    public_start_signature = (
        "pub async fn start(\n"
        "        connection: StoreRoleConnectionV1,\n"
        "        service: StoreProxyService<S>,\n"
        "    ) -> Result<Self, StoreProxyRunnerErrorV1> {"
    )
    private_start_inner_signature = (
        "async fn start_inner(\n"
        "        connection: StoreRoleConnectionV1,\n"
        "        service: StoreProxyService<S>,\n"
        "    ) -> Result<Self, StoreProxyRunnerErrorV1> {"
    )
    delegation = "Self::start_inner(connection, service).await"
    if runner.count(public_start_signature) != 1:
        raise ValueError("public_start_signature")
    if runner.count(private_start_inner_signature) != 1:
        raise ValueError("private_start_inner_signature")
    if runner.count("connection: StoreRoleConnectionV1") != 2:
        raise ValueError("store_role_connection_cardinality")
    if runner.count(delegation) != 1:
        raise ValueError("public_start_delegation")
    public_start_index = runner.index(public_start_signature)
    delegation_index = runner.index(delegation)
    private_start_inner_index = runner.index(private_start_inner_signature)
    if not public_start_index < delegation_index < private_start_inner_index:
        raise ValueError("public_start_delegation")
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
        "let response = transition\n            .proxy_store(",
        "ingress.try_send(ingress_message).is_err()",
        "service.overload_response(subject, &payload)",
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
        "let tls_client_config = read_stable_tls_client_config(&config.tls_ca_path, 1_048_576)",
        ".tls_client_config(tls_client_config)",
        ".subscription_capacity(config.subscription_capacity)",
        ".client_capacity(config.client_capacity)",
        ".read_buffer_capacity(config.read_buffer_capacity)",
    ]:
        if s.count(fragment) != 1: raise ValueError(f"private service boundary differs: {fragment}")
    if s.index("self.preflight(subject, raw)?;") > s.index("self.proxy.handle_bytes(raw)"):
        raise ValueError("private preflight occurs after store")
    if runner.index(".constant_time_matches(&service.ready_binding)") > runner.index("get_stream(&service.config.stream_name)") \
            or runner.index(".constant_time_matches(&service.ready_binding)") > runner.index(".queue_subscribe("):
        raise ValueError("Ready binding comparison occurs after external authority")
    shared_start="    async fn request_bytes_on_subject("
    shared_end="\n    #[cfg(test)]\n    pub(crate) async fn request_on_subject_for_test("
    replay_start="    pub(crate) async fn replay_canonical_request_for_test("
    replay_end="\n}\n\npub(crate) fn validate_store_proxy_client_deadline("
    for boundary in (shared_start,shared_end,replay_start,replay_end):
        if s.count(boundary)!=1: raise ValueError("shared_request_path_boundary")
    shared=s[s.index(shared_start):s.index(shared_end)]
    replay=s[s.index(replay_start):s.index(replay_end)]
    for fragment in [
        "if request_bytes.len() > self.max_request_bytes",
        ".request(subject.to_string(), request_bytes.into())",
        ".map_err(|_| PublicWitnessProxyTransportErrorV1::OutcomeUnknown)?",
        "if message.payload.len() > self.max_response_bytes",
        "WitnessStoreProxyResponseV1::decode(&message.payload)",
        "response.operation != operation || response.request_digest != request_digest",
    ]:
        if shared.count(fragment)!=1: raise ValueError(f"shared request path differs: {fragment}")
    if s.count("canonical_wire_bytes(&request)")!=1: raise ValueError("production canonicalization cardinality")
    if s.count("self.request_bytes_on_subject(bytes, operation, subject, &request_digest)")!=1:
        raise ValueError("production shared request delegation")
    if replay.count("request_bytes.to_vec(),")!=1: raise ValueError("replay byte preservation")
    if replay.count("self.request_bytes_on_subject(")!=1: raise ValueError("replay shared request delegation")
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
        "self.subscription_capacity,\n            self.client_capacity,\n            self.max_in_flight,\n            usize::from(self.read_buffer_capacity),",
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
    ("unbounded_queue", "source", "ingress.try_send(ingress_message).is_err()", "false"),
    ("omit_overload_response", "source", "service.overload_response(subject, &payload)", "None"),
    ("bypass_client_response_binding", "source", "response.operation != operation || response.request_digest != request_digest", "false"),
    ("bypass_client_operation_binding", "source", "response.operation != operation || response.request_digest != request_digest", "response.request_digest != request_digest"),
    ("bypass_client_digest_binding", "source", "response.operation != operation || response.request_digest != request_digest", "response.operation != operation"),
    ("restore_outer_timeout_classification", "source", ".map_err(|_| PublicWitnessProxyTransportErrorV1::OutcomeUnknown)?", ".map_err(|_| PublicWitnessProxyTransportErrorV1::Timeout)?"),
    ("reserialize_replay_request", "source", "request_bytes.to_vec(),", "canonical_wire_bytes(&request).unwrap(),"),
    ("bypass_production_shared_path", "source", "self.request_bytes_on_subject(bytes, operation, subject, &request_digest)", "self.request_bytes_on_subject(Vec::new(), operation, subject, &request_digest)"),
    ("arbitrary_public_store_client", "source", "pub async fn start(\n        connection: StoreRoleConnectionV1,", "pub async fn start(\n        connection: async_nats::Client,", "public_start_signature"),
    ("arbitrary_private_store_client", "source", "async fn start_inner(\n        connection: StoreRoleConnectionV1,", "async fn start_inner(\n        connection: async_nats::Client,", "private_start_inner_signature"),
    ("omit_public_start_delegation", "source", "Self::start_inner(connection, service).await", "Err(StoreProxyRunnerErrorV1::Configuration)", "public_start_delegation"),
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
    ("bypass_pinned_ca", "source", ".tls_client_config(tls_client_config)", ""),
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
for mutation in mutations:
    label, which, old, new = mutation[:4]
    expected_reason = mutation[4] if len(mutation) == 5 else None
    if values[which].count(old) != 1: raise SystemExit(f"store proxy mutation anchor differs: {label}")
    changed = values.copy(); changed[which] = changed[which].replace(old,new,1)
    combined = "\0".join(changed[key] for key in ["source","config","integration","harness","compose"])
    digests.append(hashlib.sha256(combined.encode()).hexdigest())
    try: validate(changed["source"],changed["config"],changed["integration"],changed["harness"],changed["compose"])
    except (ValueError, AttributeError) as error:
        if expected_reason is not None and str(error) != expected_reason:
            raise SystemExit(f"store proxy mutation failed for wrong reason: {label} expected={expected_reason} observed={error}") from error
        print(f"store_proxy_source_mutation_red mutation={label}")
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
  "tls_ca_swap": ("witness-store","PHASE285_WITNESS_STORE","tls://localhost","ca_configuration_refused"),
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
    exact(foreign, ["result","boundary","http_code","error_code","description"], "foreign result")
    foreign_js_refusal = foreign == {"result":"refused","boundary":"jetstream_error","http_code":404,"error_code":10059,"description":"stream not found (code 404, error code 10059)"}
    foreign_transport_refusal = foreign == {"result":"refused","boundary":"no_foreign_stream_response","http_code":None,"error_code":None,"description":"foreign account received no stream metadata"}
    if value["stream_name"] != "KV_phase285_c_account" or value["bucket_name"] != "phase285_c_account" or value["stream_id"] != "stream-phase285_c_account" or not (foreign_js_refusal or foreign_transport_refusal) or value["rogue_sequence"] != 3 or not typed_error(value["iterator_result"], "bounds") or any(not typed_error(value[key], "unavailable") for key in ["inspect_result","read_result","cas_result"]):
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
    "stream_name":"", "bucket_name":"", "stream_id":"", "foreign_result":{"result":"refused","boundary":"jetstream_error","http_code":403,"error_code":10059,"description":"stream not found (code 404, error code 10059)"},
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
        grep -qx 'phase285_transport_self_test case=phase285-raw-kv-subject positive=1 structural_mutations=44 executable_mapping_mutations=5' "$output_file" || return 1
        ;;
      transport_layering_rejects_missing_library_target)
        [ "$(grep -c '^self_test_red case=missing-library-target ' "$output_file")" -eq 1 ] &&
          grep -q '^self_test executed=1 passed=1 failed=0$' "$output_file" || return 1
        ;;
      transport_layering_rejects_zero_or_omitted_mutation)
        grep -qx 'phase285_transport_self_test case=transport-layering-zero-or-omitted positive=1 mutation_failure=1 shared_validator_mutations=2' "$output_file" || return 1
        grep -qx 'phase285_scratch_self_test site=conformance-transport boundaries=3 child_paths_created=0 passed=1' "$output_file" || return 1
        grep -qx 'phase285_scratch_self_test site=conformance-witness boundaries=3 child_paths_created=0 passed=1' "$output_file" || return 1
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

observation_source_guard() {
  python3 -I - "$ROOT_DIR/crates/swarm-governance-witness/src/public_dispatcher.rs" \
    "$ROOT_DIR/crates/swarm-governance-witness/src/store_proxy_service.rs" \
    "$ROOT_DIR/crates/swarm-governance-witness/src/lib.rs" "${1:-normal}" <<'PY'
import pathlib, sys
public_path, private_path, library_path, mode = map(str, sys.argv[1:])
sources = {"public": pathlib.Path(public_path).read_text(), "private": pathlib.Path(private_path).read_text(), "library": pathlib.Path(library_path).read_text()}
anchors = [
    ("public_observer", "public", "let observer = dispatcher.worker_observer.clone();"),
    ("private_observer", "private", "let observer = service.worker_observer.clone();"),
    ("runtime_read_head", "library", ".read_head(request.clone())"),
    ("store_records", "library", "records: Mutex<Vec<StoreObservationV1>>"),
    ("server_identity", "library", "server_client_id_for_test()"),
    ("server_authority", "library", "fn server_connection_observation("),
    ("public_store_head", "library", '"observation public head differs from authenticated store head"'),
    ("proxy_store_envelope", "library", '"observation proxy/store envelope"'),
    ("observation_ignore_boundary", "library", '#[ignore = "requires the authenticated Phase 285 NATS topology and observation artifacts"]'),
]
scope_anchors = [
    ("observation_typed_nats_proxy", "observation", "NatsPublicWitnessStoreProxyClient::new("),
    ("observation_public_shipping_start", "observation", "PublicWitnessServiceRunner::start(witness_client, dispatcher)"),
    ("observation_private_shipping_start", "observation", "StoreProxyServiceRunner::start(store_connection, store_service)"),
    ("grant_public_shipping_start", "grant", "PublicWitnessServiceRunner::start(witness_client, dispatcher)"),
    ("grant_private_shipping_start", "grant", "StoreProxyServiceRunner::start(store_connection, store_service)"),
]

def scopes(library):
    observation_start="    async fn run_worker_observation_test_async() -> Vec<u8> {"
    observation_end="\n    fn ledger_field<'a>("
    grant_start="    async fn run_response_grant_recovery_leg(leg: GrantExpiryLegV1, mode: GrantRecoveryModeV1) {"
    grant_end=(
        "\n    #[test]\n"
        "    #[ignore = \"requires the authenticated Phase 285 NATS topology and observation artifacts\"]\n"
        "    fn worker_observations_are_real_and_reconciled()"
    )
    for marker in (observation_start,observation_end,grant_start,grant_end):
        if library.count(marker)!=1: raise ValueError("observation_scope_boundary")
    return {
        "observation": library[library.index(observation_start):library.index(observation_end)],
        "grant": library[library.index(grant_start):library.index(grant_end)],
    }

def validate(candidate):
    for label, source, anchor in anchors:
        if candidate[source].count(anchor) != 1: raise ValueError(label)
    scoped=scopes(candidate["library"])
    for label, scope, anchor in scope_anchors:
        if scoped[scope].count(anchor)!=1: raise ValueError(label)
    if "Arc::new(NoopWorkerTransitionObserverV1)" in candidate["public"].split("async fn start_inner",1)[1].split("fn spawn_public_subscription",1)[0]: raise ValueError("public_observer_relabel")
    if "Arc::new(NoopWorkerTransitionObserverV1)" in candidate["private"].split("async fn start_inner",1)[1].split("pub(crate) fn admit_private_subscription_message",1)[0]: raise ValueError("private_observer_relabel")
    recording_store = candidate["library"].split("impl WitnessAtomicStore for DeadlineRecordingStoreV1",1)[1].split("struct AuthenticatedDeadlineFixtureV1",1)[0]
    if "unwrap_or_default()" in recording_store: raise ValueError("store_observation_default")
validate(sources)
if mode == "self-test":
    killed = 0
    for label, source, anchor in anchors:
        mutant = dict(sources); mutant[source] = mutant[source].replace(anchor, "/* omitted observation anchor */", 1)
        try: validate(mutant)
        except ValueError as error:
            if str(error) != label: raise SystemExit(f"observation source mutation reason differs: {label}:{error}")
            killed += 1
        else: raise SystemExit(f"observation source mutation survived: {label}")
    scoped=sources["library"]
    for label, scope, anchor in scope_anchors:
        scope_start = (
            "    async fn run_worker_observation_test_async() -> Vec<u8> {"
            if scope=="observation"
            else "    async fn run_response_grant_recovery_leg(leg: GrantExpiryLegV1, mode: GrantRecoveryModeV1) {"
        )
        prefix,body=scoped.split(scope_start,1)
        mutant=dict(sources)
        mutant["library"]=prefix+scope_start+body.replace(anchor,"/* omitted scoped shipping start */",1)
        try: validate(mutant)
        except ValueError as error:
            if str(error)!=label: raise SystemExit(f"observation scoped mutation reason differs: {label}:{error}")
            killed += 1
        else: raise SystemExit(f"observation scoped mutation survived: {label}")
    public_start="PublicWitnessServiceRunner::start(witness_client, dispatcher)"
    observation_start="    async fn run_worker_observation_test_async() -> Vec<u8> {"
    grant_start="    async fn run_response_grant_recovery_leg(leg: GrantExpiryLegV1, mode: GrantRecoveryModeV1) {"
    before_observation,after_observation=sources["library"].split(observation_start,1)
    observation_body,after_grant_prefix=after_observation.split(grant_start,1)
    cross_library=(before_observation+observation_start+observation_body.replace(public_start,"/* cross-function moved public start */",1)+grant_start+after_grant_prefix.replace(public_start,public_start+"\n        "+public_start,1))
    mutant=dict(sources); mutant["library"]=cross_library
    try: validate(mutant)
    except ValueError as error:
        if str(error)!="observation_public_shipping_start": raise SystemExit(f"observation cross-function mutation reason differs: {error}")
        killed += 1
    else: raise SystemExit("observation cross-function substitution survived")
    duplicate_library=(before_observation+observation_start+observation_body.replace(public_start,public_start+"\n        "+public_start,1)+grant_start+after_grant_prefix)
    mutant=dict(sources); mutant["library"]=duplicate_library
    try: validate(mutant)
    except ValueError as error:
        if str(error)!="observation_public_shipping_start": raise SystemExit(f"observation duplicate-in-scope mutation reason differs: {error}")
        killed += 1
    else: raise SystemExit("observation duplicate-in-scope survived")
    mutant = dict(sources); mutant["library"] = mutant["library"].replace('must(\n                    canonical_wire_bytes(ready),\n                    "store InspectReady observation serialization",\n                )', 'canonical_wire_bytes(ready).unwrap_or_default()', 1)
    try: validate(mutant)
    except ValueError as error:
        if str(error) != "store_observation_default": raise SystemExit(f"observation source mutation reason differs: store_observation_default:{error}")
        killed += 1
    else: raise SystemExit("observation source mutation survived: store_observation_default")
    print(f"observation_source_guard mutations={killed} passed=1")
else: print("observation_source_guard passed=1")
PY
}

run_service_checkpoint_observation_focus() {
  local accepted_tree="${PHASE285_SERVICE_CHECKPOINT_TREE:?PHASE285_SERVICE_CHECKPOINT_TREE required}"
  local scratch ledger token output
  [[ "$accepted_tree" =~ ^[0-9a-f]{40}$ ]] || { echo "service checkpoint observation tree is malformed" >&2; return 1; }
  observation_source_guard normal
  observation_source_guard self-test
  scratch="$(phase285_create_confined_scratch phase285-observations)"
  PHASE285_WITNESS_TEMP_DIR="$scratch"
  trap cleanup_temp_dir_on_exit EXIT
  ledger="$scratch/observations.json"
  output="$scratch/observations-test-output.txt"
  token="$(python3 -I - "$accepted_tree" <<'PY'
import hashlib, os, secrets, sys
print(hashlib.sha256((sys.argv[1] + ":" + str(os.getpid()) + ":" + secrets.token_hex(32)).encode()).hexdigest())
PY
)"
  PHASE285_OBSERVATION_LEDGER_REQUIRED=1 PHASE285_OBSERVATION_LEDGER="$ledger" \
  PHASE285_OBSERVATION_TREE="$accepted_tree" PHASE285_OBSERVATION_INVOCATION_TOKEN="$token" \
  PHASE285_OBSERVATION_CASE=service_checkpoint_observations \
    cargo test -p swarm-governance-witness --lib --locked --offline -- --test-threads=1 --ignored \
      service_checkpoint_observation_tests::worker_observations_are_real_and_reconciled --exact | tee "$output"
  grep -Fq 'test result: ok. 1 passed; 0 failed; 0 ignored;' "$output" || { echo "observation exact test counts differ" >&2; return 1; }
  ci_harness_record_passed lib \
    service_checkpoint_observation_tests::worker_observations_are_real_and_reconciled "$output"
  python3 -I - "$ledger" "$accepted_tree" "$token" "$ROOT_DIR" "$scratch" <<'PY'
import copy, hashlib, json, os, pathlib, re, selectors, signal, stat, subprocess, sys, time
path, tree, token, root_text, scratch_text = sys.argv[1:]
root, scratch = pathlib.Path(root_text), pathlib.Path(scratch_text)
raw = open(path, "rb").read()
def reject(value): raise ValueError(value)
def canonical(value): return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
if not raw.endswith(b"\n") or raw.count(b"\n") != 1: raise SystemExit("observation ledger framing differs")
row = json.loads(raw, parse_constant=reject)
if raw != canonical(row) + b"\n": raise SystemExit("observation ledger is not canonical")
expected_events = [
 {"event":"dequeued","worker":"public"},{"event":"post_preflight","worker":"public"},{"cas_attempted":False,"event":"proxy_store_begin","operation":"read_entry","worker":"public"},
 {"event":"dequeued","worker":"private"},{"event":"post_preflight","worker":"private"},{"cas_attempted":False,"event":"proxy_store_begin","operation":"read_entry","worker":"private"},
 {"cas_applied":False,"event":"proxy_store_end","operation":"read_entry","succeeded":True,"worker":"private"},{"event":"response_deadline_check","open":True,"worker":"private"},{"enqueued":True,"event":"response_enqueue_attempt","worker":"private"},
 {"cas_applied":False,"event":"proxy_store_end","operation":"read_entry","succeeded":True,"worker":"public"},{"event":"response_deadline_check","open":True,"worker":"public"},{"enqueued":True,"event":"response_enqueue_attempt","worker":"public"},
]
def digest(value): return hashlib.sha256(canonical(value)).hexdigest()
def domain_digest(domain,value):
    encoded=canonical(value)
    return hashlib.sha256(domain + len(encoded).to_bytes(8,"big") + encoded).hexdigest()
def validate(candidate):
    keys={"case","connection_client_ids","connections","counts","digests","invocation_token","operation","private_exchanges","proxy_exchanges","public_admission","public_subject","publisher","response_enqueue_attempts","request_canonical_hex","request_digest","request_nonce","response_canonical_hex","schema_version","selected_envelope_digest","selected_head_txid","selected_store_generation","selected_store_revision","selected_store_state_digest","status","store_operations","tree","worker_events"}
    if set(candidate) != keys: raise ValueError("schema")
    if candidate["schema_version"] != 1 or candidate["tree"] != tree or candidate["invocation_token"] != token or candidate["case"] != "service_checkpoint_observations" or candidate["status"] != "passed": raise ValueError("identity")
    request=json.loads(bytes.fromhex(candidate["request_canonical_hex"]),parse_constant=reject); response=json.loads(bytes.fromhex(candidate["response_canonical_hex"]),parse_constant=reject)
    if request.get("operation") != "ReadHead" or request.get("request_nonce") != candidate["request_nonce"] or request.get("request_digest") != candidate["request_digest"] or request.get("authorization",{}).get("request_digest") != candidate["request_digest"]: raise ValueError("request")
    read=response.get("Read") if isinstance(response,dict) else None
    if not isinstance(read,dict) or read.get("operation") != "ReadHead" or read.get("request_digest") != candidate["request_digest"]: raise ValueError("response")
    if candidate["operation"] != "ReadHead" or candidate["public_subject"] != "swarm.governance.witness.v1.read_head": raise ValueError("routing")
    if candidate["worker_events"] != expected_events: raise ValueError("worker_order")
    proxy,store=candidate["proxy_exchanges"],candidate["store_operations"]
    if len(proxy)!=1 or proxy[0]["operation"]!="ReadEntry" or proxy[0]["subject"]!="swarm.governance.witness.store.v1.read_entry" or proxy[0]["stream_id"]!="tom-primary": raise ValueError("proxy")
    if len(store)!=1 or store[0]["operation"]!="read_entry" or store[0]["stream_id"]!="tom-primary" or store[0]["cas_attempted"] or store[0]["cas_applied"]: raise ValueError("store")
    proxy_request=bytes.fromhex(proxy[0]["request_canonical_hex"]); proxy_response=bytes.fromhex(proxy[0]["response_canonical_hex"])
    if hashlib.sha256(proxy_request).hexdigest()!=proxy[0]["request_sha256"] or hashlib.sha256(proxy_response).hexdigest()!=proxy[0]["response_sha256"]: raise ValueError("proxy_digest")
    proxy_request_value=json.loads(proxy_request,parse_constant=reject); proxy_response_value=json.loads(proxy_response,parse_constant=reject)
    if canonical(proxy_request_value)!=proxy_request or canonical(proxy_response_value)!=proxy_response or proxy_request_value.get("operation")!="ReadEntry" or proxy_request_value.get("request_nonce")!=proxy[0]["request_nonce"] or proxy_request_value.get("request_digest")!=proxy[0]["request_digest"] or proxy_response_value.get("operation")!="ReadEntry" or proxy_response_value.get("request_digest")!=proxy[0]["request_digest"]: raise ValueError("proxy_canonical")
    store_input=bytes.fromhex(store[0]["input_canonical_hex"]); store_result=bytes.fromhex(store[0]["result_canonical_hex"])
    store_input_value=json.loads(store_input,parse_constant=reject); store_result_value=json.loads(store_result,parse_constant=reject)
    if hashlib.sha256(store_input).hexdigest()!=store[0]["input_sha256"] or hashlib.sha256(store_result).hexdigest()!=store[0]["result_sha256"] or canonical(store_input_value)!=store_input or canonical(store_result_value)!=store_result: raise ValueError("store_digest")
    for field in ("revision","store_generation","store_state_digest"):
        if proxy[0][field] != store[0][field]: raise ValueError("proxy_store_binding")
    store_entry=store_result_value.get("Entry") if isinstance(store_result_value,dict) else None
    proxy_entry=proxy_response_value.get("body",{}).get("Entry") if isinstance(proxy_response_value,dict) else None
    if not isinstance(store_entry,dict) or not isinstance(proxy_entry,dict): raise ValueError("proxy_store_envelope")
    if proxy_entry != store_entry: raise ValueError("proxy_store_envelope")
    envelope=store_entry.get("envelope")
    if not isinstance(envelope,dict): raise ValueError("proxy_store_envelope")
    preimage_keys=("schema_version","admission_digest","bucket_epoch_digest","stream_initialization_digest","stream_id","witness_identity","witness_key_id","session","last_session_rotation","current","predecessor","prepared","genesis_abort","store_generation")
    if any(key not in envelope for key in preimage_keys): raise ValueError("selected_store_binding")
    preimage={key:envelope[key] for key in preimage_keys}
    selected_state_digest=domain_digest(b"swarm.governance.witness-store.v1",preimage)
    selected_envelope_digest=domain_digest(b"swarm.governance.witness-store-signed.v1",envelope)
    if candidate["selected_store_revision"]!=store_entry.get("revision") or candidate["selected_store_generation"]!=envelope.get("store_generation") or candidate["selected_store_state_digest"]!=selected_state_digest or candidate["selected_envelope_digest"]!=selected_envelope_digest: raise ValueError("selected_store_binding")
    current=envelope.get("current")
    selected_head=current.get("head") if isinstance(current,dict) else None
    public_response=read.get("response")
    public_head=public_response.get("Head") if isinstance(public_response,dict) else None
    if not isinstance(selected_head,dict) or public_head != selected_head or candidate["selected_head_txid"]!=selected_head.get("txid") or read.get("target_txid")!=selected_head.get("txid"):
        raise ValueError("public_store_head")
    request_body=request.get("body",{}).get("ReadHead") if isinstance(request.get("body"),dict) else None
    if not isinstance(request_body,dict) or request_body.get("target_txid")!=selected_head.get("txid"): raise ValueError("public_store_head")
    response_enqueues=candidate["response_enqueue_attempts"]
    if response_enqueues != [{"enqueued":True,"ordinal":8,"worker":"private"},{"enqueued":True,"ordinal":11,"worker":"public"}]: raise ValueError("response enqueue")
    connections=candidate["connections"]
    roles=[("runtime-client","PHASE285_RUNTIME","phase285_foreign"),("public-witness","PHASE285_WITNESS","phase285_witness"),("private-store","PHASE285_WITNESS_STORE","phase285_witness_store")]
    if len(connections)!=3 or [(x["runner_role"],x["account"],x["authenticated_user"]) for x in connections]!=roles or any(not isinstance(x["server_client_id"],int) or x["server_client_id"]<=0 for x in connections) or len({x["server_client_id"] for x in connections})!=3: raise ValueError("connections")
    for connection in connections:
        evidence=bytes.fromhex(connection["server_evidence_canonical_hex"])
        if hashlib.sha256(evidence).hexdigest()!=connection["server_evidence_sha256"]: raise ValueError("connections")
        value=json.loads(evidence,parse_constant=reject)
        if canonical(value)!=evidence or value!={"account":connection["account"],"authenticated_user":connection["authenticated_user"],"server_client_id":connection["server_client_id"]}: raise ValueError("connections")
    if candidate["connection_client_ids"] != [item["server_client_id"] for item in connections]: raise ValueError("connections")
    private=candidate["private_exchanges"]
    if len(private)!=3 or [item["operation"] for item in private] != ["InspectReady","ReadEntry","ReadEntry"] or private[-1] != proxy[0]: raise ValueError("private_exchange")
    previous=0
    for item in private:
        private_request=bytes.fromhex(item["request_canonical_hex"]); private_response=bytes.fromhex(item["response_canonical_hex"])
        if hashlib.sha256(private_request).hexdigest()!=item["request_sha256"] or hashlib.sha256(private_response).hexdigest()!=item["response_sha256"]: raise ValueError("private_exchange")
        if item["request_at_nanos"] < previous or item["response_at_nanos"] < item["request_at_nanos"]: raise ValueError("private_exchange")
        previous=item["response_at_nanos"]
    admission=candidate["public_admission"]; publisher=candidate["publisher"]
    reply=publisher["reply_subject"]
    if reply!=admission["reply_subject"] or admission["subject"]!=candidate["public_subject"] or admission["payload_sha256"]!=hashlib.sha256(bytes.fromhex(candidate["request_canonical_hex"])).hexdigest() or admission["deadline_millis"]!=10000: raise ValueError("publisher_reply_subject")
    if not (reply.startswith("_INBOX.") or reply.startswith("_R_.")) or len(reply)>512 or "*" in reply or ">" in reply: raise ValueError("publisher_reply_subject")
    publisher_response=bytes.fromhex(publisher["response_canonical_hex"])
    if hashlib.sha256(publisher_response).hexdigest()!=publisher["response_sha256"] or publisher_response!=bytes.fromhex(candidate["response_canonical_hex"]): raise ValueError("publisher_response")
    if admission["received_at_nanos"]!=publisher["request_received_at_nanos"] or private[-1]["request_at_nanos"]<publisher["request_received_at_nanos"] or private[-1]["response_at_nanos"]>publisher["response_received_at_nanos"]: raise ValueError("causal_timestamps")
    arrays={"worker_events":candidate["worker_events"],"proxy_exchanges":proxy,"private_exchanges":private,"store_operations":store,"response_enqueue_attempts":response_enqueues,"connections":connections}
    counts={key:len(value) for key,value in arrays.items()}; counts.update({"cas_attempted":0,"cas_applied":0})
    if candidate["counts"] != counts: raise ValueError("counts")
    digests={key+"_sha256":digest(value) for key,value in arrays.items()}; digests.update({"request_sha256":hashlib.sha256(bytes.fromhex(candidate["request_canonical_hex"])).hexdigest(),"response_sha256":hashlib.sha256(bytes.fromhex(candidate["response_canonical_hex"])).hexdigest(),"public_admission_sha256":digest(admission),"publisher_sha256":digest(publisher),"connection_client_ids_sha256":digest(candidate["connection_client_ids"])})
    if candidate["digests"] != digests: raise ValueError("digests")
validate(row)
mutations=[]
value=copy.deepcopy(row); value["worker_events"].pop(3); mutations.append(("missing","worker_order",value))
value=copy.deepcopy(row); value["worker_events"][3],value["worker_events"][4]=value["worker_events"][4],value["worker_events"][3]; mutations.append(("reordered","worker_order",value))
value=copy.deepcopy(row); value["store_operations"].append(copy.deepcopy(value["store_operations"][0])); mutations.append(("duplicated","store",value))
value=copy.deepcopy(row); value["connections"][0]["server_client_id"]=0; mutations.append(("synthetic","connections",value))
value=copy.deepcopy(row); value["proxy_exchanges"][0]["operation"]="InspectReady"; mutations.append(("relabeled","proxy",value))
value=copy.deepcopy(row); value["request_digest"]="0"*64; mutations.append(("cross_request","request",value))
value=copy.deepcopy(row); response=json.loads(bytes.fromhex(value["response_canonical_hex"]),parse_constant=reject); response["Read"]["response"]["Head"]=None; encoded=canonical(response); value["response_canonical_hex"]=encoded.hex(); value["digests"]["response_sha256"]=hashlib.sha256(encoded).hexdigest(); mutations.append(("public_head_absent","public_store_head",value))
for name,index,field,replacement in (("account_substitution",0,"account","PHASE285_WITNESS"),("user_substitution",1,"authenticated_user","phase285_witness_store"),("client_id_substitution",2,"server_client_id",value["connections"][0]["server_client_id"])):
    mutant=copy.deepcopy(row); mutant["connections"][index][field]=replacement
    evidence={"account":mutant["connections"][index]["account"],"authenticated_user":mutant["connections"][index]["authenticated_user"],"server_client_id":mutant["connections"][index]["server_client_id"]}; encoded=canonical(evidence); mutant["connections"][index]["server_evidence_canonical_hex"]=encoded.hex(); mutant["connections"][index]["server_evidence_sha256"]=hashlib.sha256(encoded).hexdigest(); mutant["digests"]["connections_sha256"]=digest(mutant["connections"]); mutations.append((name,"connections",mutant))
for name,reason,mutant in mutations:
    try: validate(mutant)
    except ValueError as error:
        if str(error)!=reason: raise SystemExit(f"observation mutation reason differs: {name}:{error}")
    else: raise SystemExit(f"observation mutation survived: {name}")
exact_root=scratch/"observation-exact-tree"
exact_root.mkdir()
archive=subprocess.Popen(["git","-C",str(root),"archive",tree],stdout=subprocess.PIPE)
unpack=subprocess.run(["tar","-xf","-","-C",str(exact_root)],stdin=archive.stdout,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,check=False)
archive.stdout.close()
if archive.wait()!=0 or unpack.returncode!=0: raise SystemExit("observation exact-tree extraction failed")
library=exact_root/"crates/swarm-governance-witness/src/lib.rs"
source=library.read_text()
immutable='''        let response = if let Some(relay) = relay_legs.as_mut() {'''
mutable=immutable.replace("let response =", "let mut response =")
validation='''        must(response.validate(), "observation ReadHead attestation");'''
mutation='''        must(response.validate(), "observation ReadHead attestation");
        response.response = WitnessReadResponseV1::Head(Box::new(None));
        response.signature = evidence_signer.sign(&must(
            response.signing_bytes(),
            "observation mutated ReadHead signing bytes",
        ));
        must(response.validate(), "observation mutated ReadHead attestation");'''
if source.count(immutable)!=1 or source.count(validation)!=1: raise SystemExit("observation compiled head mutation anchor differs")
library.write_text(source.replace(immutable,mutable,1).replace(validation,mutation,1))
environment=os.environ.copy()
environment["CARGO_TARGET_DIR"]=str(scratch/"observation-mutant-target")
for key in ("PHASE285_OBSERVATION_LEDGER_REQUIRED","PHASE285_OBSERVATION_LEDGER","PHASE285_OBSERVATION_TREE","PHASE285_OBSERVATION_INVOCATION_TOKEN","PHASE285_OBSERVATION_CASE"):
    environment.pop(key,None)
capture_limit=16_777_216
diagnostic_limit=65_536
def fail(phase,reason,captured=b""):
    tail=captured[-diagnostic_limit:].decode("utf-8",errors="replace")
    raise SystemExit(f"observation compiled public-head phase={phase} reason={reason}\n{tail}")
def terminate(process):
    if process.poll() is None:
        try: os.killpg(process.pid,signal.SIGKILL)
        except ProcessLookupError: pass
    process.wait()
def run_bounded(command,timeout,phase):
    process=subprocess.Popen(command,cwd=exact_root,env=environment,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,start_new_session=True)
    descriptor=process.stdout.fileno(); os.set_blocking(descriptor,False)
    watcher=selectors.DefaultSelector(); watcher.register(descriptor,selectors.EVENT_READ)
    captured=bytearray(); deadline=time.monotonic()+timeout; reached_eof=False
    try:
        while not reached_eof:
            remaining=deadline-time.monotonic()
            if remaining<=0:
                terminate(process); fail(phase,"timeout",bytes(captured))
            events=watcher.select(min(0.25,remaining))
            if not events and process.poll() is not None:
                events=[(None,None)]
            for _key,_mask in events:
                try: chunk=os.read(descriptor,65_536)
                except BlockingIOError: continue
                if not chunk:
                    reached_eof=True; break
                captured.extend(chunk)
                if len(captured)>capture_limit:
                    terminate(process); fail(phase,"output-cap",bytes(captured))
        remaining=deadline-time.monotonic()
        if remaining<=0:
            terminate(process); fail(phase,"timeout",bytes(captured))
        try: return_code=process.wait(timeout=remaining)
        except subprocess.TimeoutExpired:
            terminate(process); fail(phase,"timeout",bytes(captured))
    finally:
        watcher.close(); process.stdout.close()
    return return_code,bytes(captured)
compile_command=["cargo","test","-p","swarm-governance-witness","--lib","--locked","--offline","--no-run","--message-format=json"]
compile_status,compile_output=run_bounded(compile_command,300,"compile")
if compile_status!=0: fail("compile",f"exit-{compile_status}",compile_output)
records=[]
for line in compile_output.splitlines():
    try: value=json.loads(line)
    except (UnicodeDecodeError,json.JSONDecodeError): continue
    if isinstance(value,dict): records.append(value)
finished=[value for value in records if value.get("reason")=="build-finished"]
if len(finished)!=1 or finished[0].get("success") is not True: fail("compile","build-finished",compile_output)
artifacts=[]
for value in records:
    target=value.get("target",{}); profile=value.get("profile",{})
    if value.get("reason")=="compiler-artifact" and target.get("name")=="swarm_governance_witness" and target.get("kind")==["lib"] and profile.get("test") is True and isinstance(value.get("executable"),str) and value["executable"]:
        artifacts.append(value)
if len(artifacts)!=1: fail("compile",f"executable-cardinality-{len(artifacts)}",compile_output)
target_root=pathlib.Path(environment["CARGO_TARGET_DIR"]).resolve(strict=True)
declared_executable=pathlib.Path(artifacts[0]["executable"])
try: declared_metadata=declared_executable.lstat()
except (FileNotFoundError,OSError): fail("compile","executable-declared-type",compile_output)
if not stat.S_ISREG(declared_metadata.st_mode) or stat.S_ISLNK(declared_metadata.st_mode) or declared_metadata.st_size<=0: fail("compile","executable-declared-type",compile_output)
try: executable=declared_executable.resolve(strict=True); executable.relative_to(target_root)
except (FileNotFoundError,RuntimeError,ValueError): fail("compile","executable-confinement",compile_output)
def executable_snapshot(path,phase,captured):
    metadata=path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode) or metadata.st_size<=0: fail(phase,"executable-type",captured)
    digest=hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda:source.read(1_048_576),b""): digest.update(chunk)
    return (metadata.st_size,digest.hexdigest(),metadata.st_dev,metadata.st_ino)
before=executable_snapshot(executable,"compile",compile_output)
execute_command=[str(executable),"--test-threads=1","--ignored","service_checkpoint_observation_tests::worker_observations_are_real_and_reconciled","--exact"]
execute_status,execute_output=run_bounded(execute_command,60,"execute")
if execute_status!=101: fail("execute",f"exit-{execute_status}",execute_output)
text=execute_output.decode("utf-8",errors="replace")
running=re.findall(r"^running (\d+) test$",text,re.M)
summaries=re.findall(r"^test result: FAILED\. (\d+) passed; (\d+) failed; (\d+) ignored;",text,re.M)
test_lines=re.findall(r"^test service_checkpoint_observation_tests::worker_observations_are_real_and_reconciled \.\.\. FAILED$",text,re.M)
if running!=["1"] or summaries!=[("0","1","0")] or len(test_lines)!=1: fail("execute","test-cardinality",execute_output)
panic_header=re.compile(r"^thread '([^']+)'(?: \([0-9]+\))? panicked at .+:$")
panic_records=[]
lines=text.splitlines()
for index,line in enumerate(lines):
    header=panic_header.fullmatch(line)
    if header is None: continue
    message=None
    for following in lines[index+1:]:
        if panic_header.fullmatch(following): break
        if following.strip():
            message=following; break
    if message is None: fail("execute","panic-message-missing",execute_output)
    panic_records.append((header.group(1),message))
expected_panics=[
    ("phase285-a2a-worker-observations","observation public ReadHead is absent"),
    ("service_checkpoint_observation_tests::worker_observations_are_real_and_reconciled","observation thread panicked: Any { .. }"),
]
if panic_records!=expected_panics or text.count("observation public ReadHead is absent")!=1: fail("execute","late-relation",execute_output)
if executable_snapshot(executable,"execute",execute_output)!=before: fail("execute","executable-changed",execute_output)
compile_receipt=hashlib.sha256(compile_output).hexdigest(); execute_receipt=hashlib.sha256(execute_output).hexdigest()
print(f"service_checkpoint_observation_compiled_mutation mutation=public_head_absent compiled=1 compile_sha256={compile_receipt} executable_sha256={before[1]} executed=1 execute_sha256={execute_receipt} failed=1 intended=public_store_head")
print("service_checkpoint_observations rows=1 worker=12 proxy=1 store=1 publisher=2 connections=3 cas_attempted=0 cas_applied=0 validator_mutations=10 compiled_mutations=1 passed=1")
PY
  cleanup_temp_dir
  trap - EXIT
}

run_service_checkpoint_deadline_focus() {
  local accepted_tree="${PHASE285_SERVICE_CHECKPOINT_TREE:?PHASE285_SERVICE_CHECKPOINT_TREE required}"
  local scratch ledger budget_receipt callsite_receipt constructor_receipt token output callsite_output constructor_output list_output integration_list_output
  [[ "$accepted_tree" =~ ^[0-9a-f]{40}$ ]] || {
    echo "service checkpoint deadline tree is malformed" >&2
    return 1
  }
  python3 -I - \
    "$ROOT_DIR/crates/swarm-governance-witness/src/lib.rs" \
    "$ROOT_DIR/crates/swarm-governance-witness/src/store_proxy_service.rs" \
    "$ROOT_DIR/crates/swarm-governance-witness/src/public_dispatcher.rs" \
    "$ROOT_DIR/tools/check-phase285-witness-conformance.sh" <<'PY'
import re, sys
library, private, public, checker = [open(path, encoding="utf-8").read() for path in sys.argv[1:]]
if private.count("pub(crate) fn admit_private_subscription_message(") != 1:
    raise SystemExit("private subscriber admission visibility differs")
if public.count("pub(crate) fn admit_public_subscription_message(") != 1:
    raise SystemExit("public subscriber admission visibility differs")
private_test = re.search(r"async fn run_private_queue_expired\((.*?)\n    async fn run_public_queue_expired", library, re.S)
public_test = re.search(r"async fn run_public_queue_expired\((.*?)\n    async fn run_private_read", library, re.S)
if private_test is None or private_test.group(1).count("async_nats::Message {") != 1 or private_test.group(1).count("admit_private_subscription_message(") != 1 or ".send(PrivateIngressMessage {" in private_test.group(1):
    raise SystemExit("private exact FQN raw admission path differs")
if public_test is None or public_test.group(1).count("async_nats::Message {") != 1 or public_test.group(1).count("admit_public_subscription_message(") != 1 or ".send(PublicIngressMessage {" in public_test.group(1):
    raise SystemExit("public exact FQN raw admission path differs")
labels = [
    f"{side}_subscriber_{family}"
    for side in ("private", "public")
    for family in ("capture_reset", "capture_after_queue", "overlong_deadline")
]
if any(checker.count(f'("{label}",') != 1 for label in labels):
    raise SystemExit("subscriber admission mutation inventory differs")
print("deadline_admission_source_guard passed=1 mutations=6")
PY
  scratch="$(phase285_create_confined_scratch phase285-deadline)"
  PHASE285_WITNESS_TEMP_DIR="$scratch"
  trap cleanup_temp_dir_on_exit EXIT
  ledger="$scratch/deadline-ledger.jsonl"
  budget_receipt="$scratch/deadline-budget.json"
  callsite_receipt="$scratch/deadline-callsite.json"
  constructor_receipt="$scratch/deadline-constructor.json"
  token="$(python3 -I - "$accepted_tree" <<'PY'
import hashlib, os, secrets, sys
print(hashlib.sha256((sys.argv[1] + ":" + str(os.getpid()) + ":" + secrets.token_hex(32)).encode()).hexdigest())
PY
)"
  output="$scratch/deadline-test-output.txt"
  callsite_output="$scratch/deadline-callsite-output.txt"
  constructor_output="$scratch/deadline-constructor-output.txt"
  list_output="$scratch/deadline-list-output.txt"
  integration_list_output="$scratch/deadline-integration-list-output.txt"

  cargo test -p swarm-governance-witness --lib --locked --offline -- --list >"$list_output"
  [ "$(grep -Fxc 'deadline_state_machine_tests::deadline_state_machine_is_receipt_anchored_and_mutation_sensitive: test' "$list_output")" -eq 1 ] || {
    echo "deadline test inventory differs" >&2
    return 1
  }
  [ "$(grep -Fxc 'deadline_state_machine_tests::subscriber_callsite_is_receipt_anchored_and_mutation_sensitive: test' "$list_output")" -eq 1 ] || {
    echo "deadline callsite test inventory differs" >&2
    return 1
  }
  cargo test -p swarm-governance-witness --test full_service_path --locked --offline -- --list >"$integration_list_output"
  [ "$(grep -Fxc 'full_service_path_constructor_deadline_is_exact_and_receipt_bound: test' "$integration_list_output")" -eq 1 ] || {
    echo "deadline constructor test inventory differs" >&2
    return 1
  }
  PHASE285_DEADLINE_LEDGER_REQUIRED=1 \
  PHASE285_DEADLINE_LEDGER="$ledger" \
  PHASE285_DEADLINE_BUDGET_RECEIPT="$budget_receipt" \
  PHASE285_DEADLINE_TREE="$accepted_tree" \
  PHASE285_DEADLINE_INVOCATION_TOKEN="$token" \
  PHASE285_DEADLINE_CASE=service_checkpoint_deadline \
    cargo test -p swarm-governance-witness --lib --locked --offline \
      deadline_state_machine_tests::deadline_state_machine_is_receipt_anchored_and_mutation_sensitive \
      -- --exact --test-threads=1 | tee "$output"
  grep -Fq 'test result: ok. 1 passed; 0 failed; 0 ignored;' "$output" || {
    echo "deadline exact test counts differ" >&2
    return 1
  }
  PHASE285_DEADLINE_CALLSITE_RECEIPT="$callsite_receipt" \
  PHASE285_DEADLINE_TREE="$accepted_tree" \
  PHASE285_DEADLINE_INVOCATION_TOKEN="$token" \
  PHASE285_DEADLINE_CASE=service_checkpoint_deadline \
    cargo test -p swarm-governance-witness --lib --locked --offline \
      deadline_state_machine_tests::subscriber_callsite_is_receipt_anchored_and_mutation_sensitive \
      -- --ignored --exact --test-threads=1 | tee "$callsite_output"
  grep -Fq 'test result: ok. 1 passed; 0 failed; 0 ignored;' "$callsite_output" || {
    echo "deadline callsite exact test counts differ" >&2
    return 1
  }
  ci_harness_record_passed lib \
    deadline_state_machine_tests::subscriber_callsite_is_receipt_anchored_and_mutation_sensitive \
    "$callsite_output"
  PHASE285_DEADLINE_CONSTRUCTOR_RECEIPT="$constructor_receipt" \
  PHASE285_DEADLINE_TREE="$accepted_tree" \
  PHASE285_DEADLINE_INVOCATION_TOKEN="$token" \
  PHASE285_DEADLINE_CASE=service_checkpoint_deadline \
  PHASE285_WITNESS_INTEGRITY_LAUNCHER_SHA256="$(shasum -a 256 "$ROOT_DIR/tools/check-phase285-witness-integrity.sh" | awk '{print $1}')" \
  PHASE285_WITNESS_INTEGRITY_MANIFEST_SHA256="$(shasum -a 256 "$ROOT_DIR/tools/fixtures/phase285-witness-integrity.json" | awk '{print $1}')" \
    cargo test -p swarm-governance-witness --test full_service_path --locked --offline \
      full_service_path_constructor_deadline_is_exact_and_receipt_bound \
      -- --ignored --exact --test-threads=1 | tee "$constructor_output"
  grep -Fq 'test result: ok. 1 passed; 0 failed; 0 ignored;' "$constructor_output" || {
    echo "deadline constructor exact test counts differ" >&2
    return 1
  }
  ci_harness_record_passed full_service_path \
    full_service_path_constructor_deadline_is_exact_and_receipt_bound "$constructor_output"

  python3 -I - "$ledger" "$budget_receipt" "$callsite_receipt" "$constructor_receipt" "$accepted_tree" "$token" \
    "$ROOT_DIR/crates/swarm-governance-witness/src/service_config.rs" \
    "$ROOT_DIR/crates/swarm-governance-witness/src/store_proxy_service.rs" \
    "$ROOT_DIR/crates/swarm-governance-witness/src/public_dispatcher.rs" \
    "$ROOT_DIR/crates/swarm-governance-witness/src/lib.rs" \
    "$ROOT_DIR/crates/swarm-governance-witness/tests/full_service_path.rs" \
    "$ROOT_DIR" "$scratch" "$list_output" \
    "$(shasum -a 256 "$ROOT_DIR/tools/check-phase285-witness-integrity.sh" | awk '{print $1}')" \
    "$(shasum -a 256 "$ROOT_DIR/tools/fixtures/phase285-witness-integrity.json" | awk '{print $1}')" <<'PY'
import copy, hashlib, json, os, pathlib, re, selectors, shutil, signal, stat, subprocess, sys, time
ledger, budget_receipt, callsite_receipt, constructor_receipt, tree, token, config_path, private_path, public_path, library_path, fixture_path, root_path, scratch_path, list_path, launcher_pin, manifest_pin = sys.argv[1:]
ledger = pathlib.Path(ledger)
budget_receipt = pathlib.Path(budget_receipt)
callsite_receipt = pathlib.Path(callsite_receipt)
constructor_receipt = pathlib.Path(constructor_receipt)
root = pathlib.Path(root_path).resolve(strict=True)
scratch = pathlib.Path(scratch_path).resolve(strict=True)

def reject_constant(value):
    raise ValueError(value)

def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()

raw_lines = ledger.read_bytes().splitlines(keepends=True)
if len(raw_lines) != 8 or any(not line.endswith(b"\n") for line in raw_lines):
    raise SystemExit("deadline ledger framing/cardinality differs")
rows = []
for line in raw_lines:
    value = json.loads(line, parse_constant=reject_constant)
    if line != canonical(value) + b"\n":
        raise SystemExit("deadline ledger row is not canonical")
    rows.append(value)

def read_canonical_receipt(path, label):
    raw = path.read_bytes()
    if not raw.endswith(b"\n") or raw.count(b"\n") != 1:
        raise SystemExit(f"deadline {label} receipt framing differs")
    value = json.loads(raw, parse_constant=reject_constant)
    if raw != canonical(value) + b"\n":
        raise SystemExit(f"deadline {label} receipt is not canonical")
    return value

budget = read_canonical_receipt(budget_receipt, "budget")
callsite = read_canonical_receipt(callsite_receipt, "callsite")
constructor = read_canonical_receipt(constructor_receipt, "constructor")

counter_keys = {"queue_dequeues","preflights","store_calls","private_proxy_calls","cas_attempted","cas_applied","retries","response_enqueues","outcome_unknown"}
evidence_keys = counter_keys | {"ordered_trace"}
zero = {key: (False if key == "outcome_unknown" else 0) for key in counter_keys}
def dequeued(worker): return {"event":"dequeued","worker":worker}
def preflight(worker): return {"event":"post_preflight","worker":worker}
def begin(worker, operation, attempted=False): return {"cas_attempted":attempted,"event":"proxy_store_begin","operation":operation,"worker":worker}
def end(worker, operation, succeeded, applied=False): return {"cas_applied":applied,"event":"proxy_store_end","operation":operation,"succeeded":succeeded,"worker":worker}
def deadline(worker, open): return {"event":"response_deadline_check","open":open,"worker":worker}
expected = [
    ("private_queue_expired", {**zero,"queue_dequeues":1,"ordered_trace":[dequeued("private")]}),
    ("private_preflight_expired", {**zero,"queue_dequeues":1,"preflights":1,"ordered_trace":[dequeued("private"),preflight("private")]}),
    ("private_store_crosses_deadline", {**zero,"queue_dequeues":1,"preflights":1,"store_calls":1,"ordered_trace":[dequeued("private"),preflight("private"),begin("private","read_entry")]}),
    ("private_response_enqueue_expired", {**zero,"queue_dequeues":1,"preflights":1,"store_calls":1,"ordered_trace":[dequeued("private"),preflight("private"),begin("private","read_entry"),end("private","read_entry",True),deadline("private",False)]}),
    ("public_queue_expired", {**zero,"queue_dequeues":1,"ordered_trace":[dequeued("public")]}),
    ("public_private_exchange_crosses_deadline", {**zero,"queue_dequeues":1,"preflights":1,"private_proxy_calls":1,"outcome_unknown":True,"ordered_trace":[dequeued("public"),preflight("public"),begin("public","read_entry"),end("public","read_entry",False),{"event":"outcome_unknown"}]}),
    ("public_response_enqueue_expired", {**zero,"queue_dequeues":1,"preflights":1,"private_proxy_calls":1,"ordered_trace":[dequeued("public"),preflight("public"),begin("public","read_entry"),end("public","read_entry",True),deadline("public",False)]}),
    ("post_cas_timeout_outcome_unknown", {**zero,"queue_dequeues":1,"preflights":1,"private_proxy_calls":3,"cas_attempted":1,"cas_applied":1,"outcome_unknown":True,"ordered_trace":[dequeued("public"),preflight("public"),begin("public","read_entry"),end("public","read_entry",True),begin("public","compare_and_swap",True),{"event":"cas_applied_observation","worker":"private"},end("public","compare_and_swap",False),begin("public","read_entry"),end("public","read_entry",False),{"event":"outcome_unknown"}]}),
]
topology = {"private_handler_millis":2000,"private_response_grant_millis":3000,"public_handler_millis":10000,"public_response_grant_millis":12000,"private_handler_reserve_millis":1000,"public_private_reserve_millis":1000,"public_handler_reserve_millis":2000,"response_grant_maximum":1}
constructor_observations = [
    {"input_millis":0,"result":"refused"},
    {"input_millis":2999,"result":"refused"},
    {"input_millis":3000,"result":"accepted"},
    {"input_millis":3001,"result":"refused"},
    {"input_millis":18446744073709551615,"result":"refused"},
]

def validate(candidate, budget_value=budget, callsite_value=callsite, constructor_value=constructor):
    if len(candidate) != 8:
        raise ValueError("row cardinality")
    for index, (row, (inner_id, evidence)) in enumerate(zip(candidate, expected)):
        if set(row) != {"schema_version","tree","invocation_token","case","inner_id","status","live_nats_grants_proved","evidence"}:
            raise ValueError("row schema")
        if row["schema_version"] != 1 or row["tree"] != tree or row["invocation_token"] != token or row["case"] != "service_checkpoint_deadline" or row["inner_id"] != inner_id or row["status"] != "passed" or row["live_nats_grants_proved"] is not False:
            raise ValueError("row identity/status")
        if set(row["evidence"]) != evidence_keys or row["evidence"] != evidence:
            raise ValueError("row evidence")
    traces = [canonical(row["evidence"]["ordered_trace"]) for row in candidate]
    if len(set(traces)) != 8 or any(not row["evidence"]["ordered_trace"] for row in candidate):
        raise ValueError("ordered trace pairwise evidence")

    if set(budget_value) != {"schema_version","tree","invocation_token","case","inner_id","status","live_nats_grants_proved","topology"} or budget_value != {
        "schema_version":1,"tree":tree,"invocation_token":token,"case":"service_checkpoint_deadline",
        "inner_id":"deadline_budget_constructor_exact","status":"passed","live_nats_grants_proved":False,"topology":topology,
    }:
        raise ValueError("budget receipt")
    callsite_keys = {"schema_version","tree","invocation_token","case","private","public","private_backend_calls","public_backend_calls","private_second_responses","public_second_responses"}
    if set(callsite_value) != callsite_keys or callsite_value["schema_version"] != 1 or callsite_value["tree"] != tree or callsite_value["invocation_token"] != token or callsite_value["case"] != "service_checkpoint_deadline":
        raise ValueError("callsite receipt identity")
    receipt_identities = []
    for key, worker, deadline in [("private","private",2000),("public","public",10000)]:
        receipt = callsite_value[key]
        if set(receipt) != {"worker","subject","payload_sha256","payload","deadline_identity","reply","deadline_millis"} or receipt["worker"] != worker or receipt["deadline_millis"] != deadline or not re.fullmatch(r"[0-9a-f]{64}", receipt["payload_sha256"]):
            raise ValueError(f"callsite {key} receipt")
        payload = receipt["payload"]
        identity = receipt["deadline_identity"]
        if not isinstance(payload, list) or any(not isinstance(byte, int) or isinstance(byte, bool) or not 0 <= byte <= 255 for byte in payload) or hashlib.sha256(bytes(payload)).hexdigest() != receipt["payload_sha256"] or not isinstance(identity, int) or isinstance(identity, bool) or identity <= 0:
            raise ValueError(f"callsite {key} receipt binding")
        receipt_identities.append(identity)
    if len(set(receipt_identities)) != 2:
        raise ValueError("callsite receipt deadline identity reuse")
    if callsite_value["private_backend_calls"] != 1 or callsite_value["public_backend_calls"] != 1 or callsite_value["private_second_responses"] != 0 or callsite_value["public_second_responses"] != 0:
        raise ValueError("callsite backend/response facts")
    constructor_keys = {"schema_version","tree","invocation_token","case","inner_id","status","live_nats_grants_proved","launcher_sha256","manifest_sha256","observations","observations_sha256","store_calls"}
    if set(constructor_value) != constructor_keys or constructor_value["schema_version"] != 1 or constructor_value["tree"] != tree or constructor_value["invocation_token"] != token or constructor_value["case"] != "service_checkpoint_deadline" or constructor_value["inner_id"] != "deadline_budget_constructor_exact" or constructor_value["status"] != "passed" or constructor_value["live_nats_grants_proved"] is not False or constructor_value["launcher_sha256"] != launcher_pin or constructor_value["manifest_sha256"] != manifest_pin or not launcher_pin or not manifest_pin or constructor_value["observations"] != constructor_observations or constructor_value["observations_sha256"] != hashlib.sha256(canonical(constructor_observations)).hexdigest() or constructor_value["store_calls"] != 0:
        raise ValueError("constructor receipt")

validate(rows)
mutants = []
mutants.append(("omission", rows[:-1]))
mutants.append(("addition", rows + [copy.deepcopy(rows[-1])]))
duplicate = copy.deepcopy(rows); duplicate[1] = copy.deepcopy(duplicate[0]); mutants.append(("duplication", duplicate))
renamed = copy.deepcopy(rows); renamed[0]["inner_id"] = "renamed"; mutants.append(("renamed_id", renamed))
wrong_status = copy.deepcopy(rows); wrong_status[0]["status"] = "failed"; mutants.append(("wrong_status", wrong_status))
wrong_count = copy.deepcopy(rows); wrong_count[2]["evidence"]["store_calls"] = 0; mutants.append(("fabricated_counter", wrong_count))
wrong_token = copy.deepcopy(rows); wrong_token[0]["invocation_token"] = "0"*64; mutants.append(("stale_token", wrong_token))
wrong_tree = copy.deepcopy(rows); wrong_tree[0]["tree"] = "0"*40; mutants.append(("stale_tree", wrong_tree))
wrong_case = copy.deepcopy(rows); wrong_case[0]["case"] = "other"; mutants.append(("cross_case", wrong_case))
late_enqueue = copy.deepcopy(rows); late_enqueue[3]["evidence"]["response_enqueues"] = 1; mutants.append(("late_response_enqueue", late_enqueue))
downgrade = copy.deepcopy(rows); downgrade[7]["evidence"]["outcome_unknown"] = False; mutants.append(("cas_ambiguity_downgrade", downgrade))
trace_copy = copy.deepcopy(rows); trace_copy[3]["evidence"]["ordered_trace"] = copy.deepcopy(trace_copy[2]["evidence"]["ordered_trace"]); mutants.append(("row_trace_copy", trace_copy))
trace_swap = copy.deepcopy(rows); trace_swap[2]["evidence"]["ordered_trace"], trace_swap[3]["evidence"]["ordered_trace"] = trace_swap[3]["evidence"]["ordered_trace"], trace_swap[2]["evidence"]["ordered_trace"]; mutants.append(("row_trace_swap", trace_swap))
grant_claim = copy.deepcopy(budget); grant_claim["live_nats_grants_proved"] = True; mutants.append(("live_nats_grant_claim", rows, grant_claim, callsite, constructor))
callsite_counter = copy.deepcopy(callsite); callsite_counter["private_backend_calls"] = 0; mutants.append(("callsite_counter_fabrication", rows, budget, callsite_counter, constructor))
callsite_deadline = copy.deepcopy(callsite); callsite_deadline["public"]["deadline_millis"] = 10001; mutants.append(("callsite_deadline_substitution", rows, budget, callsite_deadline, constructor))
constructor_input = copy.deepcopy(constructor); constructor_input["observations"][1]["input_millis"] = 2998; mutants.append(("constructor_input_substitution", rows, budget, callsite, constructor_input))
constructor_result = copy.deepcopy(constructor); constructor_result["observations"][2]["result"] = "refused"; mutants.append(("constructor_result_fabrication", rows, budget, callsite, constructor_result))
normalized_mutants = [(name, candidate, budget, callsite, constructor) for name, candidate in mutants[:13]] + mutants[13:]
if len(normalized_mutants) != 18:
    raise SystemExit("deadline ledger mutation inventory differs")
for name, candidate, budget_candidate, callsite_candidate, constructor_candidate in normalized_mutants:
    try: validate(candidate, budget_candidate, callsite_candidate, constructor_candidate)
    except ValueError: print(f"deadline_ledger_mutation_red mutation={name}")
    else: raise SystemExit(f"deadline ledger mutation survived: {name}")

sources = {
    "config": pathlib.Path(config_path).read_text(),
    "private": pathlib.Path(private_path).read_text(),
    "public": pathlib.Path(public_path).read_text(),
    "library": pathlib.Path(library_path).read_text(),
    "fixture": pathlib.Path(fixture_path).read_text(),
}

required = {
    "config": [
        "STORE_HANDLER_DEADLINE_MILLIS: u64 = 2_000",
        "STORE_RESPONSE_GRANT_MILLIS: u64 = 3_000",
        "PUBLIC_HANDLER_DEADLINE_MILLIS: u64 = 10_000",
        "PUBLIC_RESPONSE_GRANT_MILLIS: u64 = 12_000",
        "RESPONSE_GRANT_MAXIMUM: usize = 1",
        "timeout_at(self.at, future)",
        "pub(crate) struct WorkerTransitionV1",
        "pub(crate) async fn run_observed_worker_message",
        "transition.publish(publisher, reply, bytes).await",
    ],
    "private": [
        "ReceiptDeadlineV1::private()",
        "Self::start_inner(connection, service).await",
        "admit_private_subscription_message(",
        "admission_observer.accepted(receipt);",
        "run_private_worker_message",
        "run_observed_worker_message(",
        "transition.post_preflight();",
        "pub(crate) async fn handle_subject_bytes_before",
        ".proxy_store(",
    ],
    "public": [
        "ReceiptDeadlineV1::public()",
        "Self::start_inner(client, dispatcher).await",
        "admit_public_subscription_message(",
        "admission_observer.accepted(receipt);",
        "value.starts_with(\"_R_.\")",
        "run_public_worker_message",
        "run_observed_worker_message(",
        "transition.post_preflight();",
        "if transition.ensure_open().is_err()",
        "ACTIVE_CAS_ATTEMPTED",
        "transition.outcome_unknown();",
    ],
    "library": [
        "impl WitnessAtomicStore for DeadlineRecordingStoreV1",
        "StoreProxyService::new(service_config, ready.clone(), store)",
        "run_private_worker_message(",
        "receive_and_run_private_worker_message(",
        "PublicWitnessDispatcher::new(",
        "run_public_worker_message(",
        "receive_and_run_public_worker_message(",
        "CAS-applied event diverged from recording WitnessAtomicStore",
        "fixture.facts.cas_applied.load(Ordering::SeqCst), 1",
        "subscriber_callsite_is_receipt_anchored_and_mutation_sensitive",
        "PublicWitnessServiceRunner::start(",
        "StoreProxyServiceRunner::start(",
        "write_deadline_budget_receipt(topology);",
    ],
    "fixture": ["[0, 2_999, 3_000, 3_001, u64::MAX]", "deadline_r24_constructor_results", "NatsPublicWitnessStoreProxyClient::new("],
}

def source_validate(candidate):
    for name, fragments in required.items():
        for fragment in fragments:
            if fragment not in candidate[name]:
                raise ValueError(f"{name}:{fragment}")
    if candidate["private"].count("ReceiptDeadlineV1::private()") < 2:
        raise ValueError("private receipt cardinality")
    if candidate["public"].count("ReceiptDeadlineV1::public()") < 3:
        raise ValueError("public receipt cardinality")
    if "request_deadline_millis != STORE_RESPONSE_GRANT_MILLIS" not in candidate["private"]:
        raise ValueError("constructor exact deadline")
    if "RecordedOperationV1" in candidate["library"] or "async fn operation(" in candidate["library"]:
        raise ValueError("synthetic operation helper")

# Cardinality-special fragments are checked separately from the one-use list.
required["private"].remove("ReceiptDeadlineV1::private()")
required["public"].remove("ReceiptDeadlineV1::public()")
source_validate(sources)
source_mutations = [
    ("receipt_reset", "private", "receipt_deadline: ReceiptDeadlineV1::private()", "receipt_deadline: ReceiptDeadlineV1::from_now(3_000)"),
    ("private_queue_check", "private", "run_observed_worker_message(", "run_observed_worker_message_bypassed("),
    ("private_pre_store_check", "private", "if transition.ensure_open().is_err()", "if false"),
    ("public_queue_check", "public", "run_observed_worker_message(", "run_observed_worker_message_bypassed("),
    ("public_pre_store_check", "public", "if transition.ensure_open().is_err()", "if false"),
    ("relative_timeout", "config", "timeout_at(self.at, future)", "tokio::time::timeout(Duration::from_secs(1), future)"),
    ("late_publish", "config", "transition.publish(publisher, reply, bytes).await", "publisher.publish(reply, bytes).await"),
    ("retry", "public", "transition.outcome_unknown();", "continue;"),
    ("cas_downgrade", "public", "transition.outcome_unknown();", "return Err(PublicWitnessDispatchErrorV1::Timeout);"),
    ("topology", "config", "STORE_RESPONSE_GRANT_MILLIS: u64 = 3_000", "STORE_RESPONSE_GRANT_MILLIS: u64 = 3_001"),
    ("constructor", "private", "request_deadline_millis != STORE_RESPONSE_GRANT_MILLIS", "request_deadline_millis == 0"),
    ("recording_store_bypassed", "library", "impl WitnessAtomicStore for DeadlineRecordingStoreV1", "impl DeadlineRecordingStoreV1"),
    ("private_service_bypassed", "library", "run_private_worker_message(", "run_observed_worker_message("),
    ("public_dispatcher_bypassed", "library", "PublicWitnessDispatcher::new(", "PublicWitnessDispatcher::new_bypassed("),
    ("public_worker_bypassed", "library", "run_public_worker_message(", "run_observed_worker_message("),
    ("cas_fact_fabricated", "library", "evidence.cas_applied = cas_applied;", "evidence.cas_applied = 1;"),
    ("cas_fact_assertion_omitted", "library", "fixture.facts.cas_applied.load(Ordering::SeqCst), 1", "fixture.facts.cas_applied.load(Ordering::SeqCst), 0"),
]
# These lexical controls are retained as defense in depth but are explicitly
# excluded from the r20 executable mutation count below.
source_mutations = []
digests = set()
for label, path, old, new in source_mutations:
    candidate = dict(sources)
    if candidate[path].count(old) == 0:
        raise SystemExit(f"deadline source mutation anchor differs: {label}")
    candidate[path] = candidate[path].replace(old, new)
    digest = hashlib.sha256("\0".join(candidate[name] for name in sorted(candidate)).encode()).hexdigest()
    if digest in digests: raise SystemExit("deadline source mutation digest duplicated")
    digests.add(digest)
    try: source_validate(candidate)
    except ValueError: print(f"deadline_source_mutation_red mutation={label}")
    else: raise SystemExit(f"deadline source mutation survived: {label}")
print(f"deadline_focus_lexical rows=9 ledger_mutations={len(mutants)} lexical_source_mutations={len(source_mutations)}")

exact_root = scratch / "deadline-exact-tree"
exact_root.mkdir()
archive = subprocess.Popen(
    ["git", "-C", str(root), "archive", tree], stdout=subprocess.PIPE
)
unpack = subprocess.run(
    ["tar", "-xf", "-", "-C", str(exact_root)],
    stdin=archive.stdout,
    stdout=subprocess.PIPE,
    stderr=subprocess.STDOUT,
    text=False,
    check=False,
)
archive.stdout.close()
archive_status = archive.wait()
if archive_status != 0 or unpack.returncode != 0:
    raise SystemExit("deadline exact-tree extraction failed")

target = scratch / "deadline-shared-target"
if target.exists():
    raise SystemExit("deadline shared target is not fresh")
base_environment = os.environ.copy()
base_environment["CARGO_TARGET_DIR"] = str(target)
for name in ["PHASE285_DEADLINE_LEDGER", "PHASE285_DEADLINE_LEDGER_REQUIRED", "PHASE285_DEADLINE_BUDGET_RECEIPT", "PHASE285_DEADLINE_CALLSITE_RECEIPT", "PHASE285_DEADLINE_CONSTRUCTOR_RECEIPT", "PHASE285_DEADLINE_TREE", "PHASE285_DEADLINE_INVOCATION_TOKEN", "PHASE285_DEADLINE_CASE"]:
    base_environment.pop(name, None)

def cargo(arguments, cwd=exact_root, extra_environment=None):
    environment = base_environment.copy()
    if extra_environment:
        environment.update(extra_environment)
    return subprocess.run(
        ["cargo", *arguments], cwd=cwd, env=environment, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False,
        timeout=120,
    )

boundary_capture_limit = 16_777_216
boundary_diagnostic_limit = 65_536
boundary_timeout_seconds = 300
boundary_seed_timeout_seconds = 900

def boundary_failure(receipt, phase, reason, timeout_seconds, captured=b"", receipt_started_ns=None):
    elapsed_ms = None
    if receipt_started_ns is not None:
        elapsed_ms = (time.monotonic_ns() - receipt_started_ns) // 1_000_000
    elapsed_field = "" if elapsed_ms is None else f" elapsed_ms={elapsed_ms}"
    print(
        f"deadline_boundary_progress receipt={receipt} phase={phase} state=failed timeout_seconds={timeout_seconds} reason={reason}{elapsed_field}",
        flush=True,
    )
    tail = captured[-boundary_diagnostic_limit:].decode("utf-8", errors="replace")
    raise SystemExit(
        f"deadline {receipt} bounded build failed phase={phase} reason={reason}{elapsed_field}\n{tail}"
    )

def terminate_boundary_process(process):
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)

def boundary_environment(parent_environment):
    environment = parent_environment.copy()
    for name in list(environment):
        if name in {"RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER"} or name.startswith("SCCACHE_"):
            environment.pop(name, None)
    # The parent CI environment deliberately enables Cargo color globally.
    # This parser consumes a mixed JSON/progress stream and rejects unknown
    # non-JSON lines, so ANSI decoration would turn Cargo's documented
    # `Compiling`/`Checking`/`Finished` progress into a false unknown token on
    # a cold cache. Bind the child producer to undecorated output instead of
    # weakening the parser to strip arbitrary terminal control sequences.
    environment["CARGO_TERM_COLOR"] = "never"
    return environment

hostile_color_environment = base_environment.copy()
hostile_color_environment["CARGO_TERM_COLOR"] = "always"
if boundary_environment(hostile_color_environment).get("CARGO_TERM_COLOR") != "never":
    raise SystemExit("deadline boundary environment retained hostile Cargo color")
print("deadline_boundary_environment_self_test hostile_cargo_color=always child_cargo_color=never")

def run_boundary_command(receipt, arguments, timeout_seconds, receipt_started_ns):
    environment = boundary_environment(base_environment)
    command = ["cargo", *arguments, "--message-format=json"]
    print(
        f"deadline_boundary_progress receipt={receipt} phase=compile state=start timeout_seconds={timeout_seconds} reason=none",
        flush=True,
    )
    try:
        process = subprocess.Popen(
            command,
            cwd=exact_root,
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
    except OSError:
        boundary_failure(
            receipt, "compile", "spawn", timeout_seconds, receipt_started_ns=receipt_started_ns
        )
    descriptor = process.stdout.fileno()
    os.set_blocking(descriptor, False)
    watcher = selectors.DefaultSelector()
    watcher.register(descriptor, selectors.EVENT_READ)
    captured = bytearray()
    deadline = (receipt_started_ns / 1_000_000_000) + timeout_seconds
    reached_eof = False
    try:
        while not reached_eof:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                terminate_boundary_process(process)
                boundary_failure(
                    receipt, "compile", "timeout", timeout_seconds, bytes(captured), receipt_started_ns
                )
            events = watcher.select(min(0.25, remaining))
            if not events and process.poll() is not None:
                events = [(None, None)]
            for _key, _mask in events:
                try:
                    chunk = os.read(descriptor, 65_536)
                except BlockingIOError:
                    continue
                if not chunk:
                    reached_eof = True
                    break
                if len(captured) + len(chunk) > boundary_capture_limit:
                    remaining_capacity = boundary_capture_limit - len(captured)
                    if remaining_capacity > 0:
                        captured.extend(chunk[:remaining_capacity])
                    terminate_boundary_process(process)
                    boundary_failure(
                        receipt,
                        "compile",
                        "output-overflow",
                        timeout_seconds,
                        bytes(captured),
                        receipt_started_ns,
                    )
                captured.extend(chunk)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            terminate_boundary_process(process)
            boundary_failure(
                receipt, "compile", "timeout", timeout_seconds, bytes(captured), receipt_started_ns
            )
        try:
            return_code = process.wait(timeout=remaining)
        except subprocess.TimeoutExpired:
            terminate_boundary_process(process)
            boundary_failure(
                receipt, "compile", "timeout", timeout_seconds, bytes(captured), receipt_started_ns
            )
    finally:
        watcher.close()
        process.stdout.close()
    return return_code, bytes(captured)

def boundary_artifact_snapshot(
    receipt,
    declared,
    declared_metadata,
    target_root,
    artifact,
    timeout_seconds,
    captured,
    receipt_started_ns,
):
    declared_identity = (
        declared_metadata.st_size,
        declared_metadata.st_dev,
        declared_metadata.st_ino,
        declared_metadata.st_mode,
    )
    if not hasattr(os, "O_NOFOLLOW"):
        boundary_failure(
            receipt, "artifact", "no-open-nofollow", timeout_seconds, captured, receipt_started_ns
        )
    flags = os.O_RDONLY | os.O_NOFOLLOW
    try:
        descriptor = os.open(declared, flags)
    except OSError:
        boundary_failure(
            receipt, "artifact", "artifact-open", timeout_seconds, captured, receipt_started_ns
        )
    try:
        opened = os.fstat(descriptor)
        opened_identity = (opened.st_size, opened.st_dev, opened.st_ino, opened.st_mode)
        if opened_identity != declared_identity or not stat.S_ISREG(opened.st_mode) or opened.st_size <= 0:
            boundary_failure(
                receipt,
                "artifact",
                "artifact-open-identity",
                timeout_seconds,
                captured,
                receipt_started_ns,
            )
        digest = hashlib.sha256()
        length = 0
        while True:
            chunk = os.read(descriptor, 1_048_576)
            if not chunk:
                break
            digest.update(chunk)
            length += len(chunk)
        after_open = os.fstat(descriptor)
        after_open_identity = (
            after_open.st_size,
            after_open.st_dev,
            after_open.st_ino,
            after_open.st_mode,
        )
    except OSError:
        boundary_failure(
            receipt, "artifact", "artifact-read", timeout_seconds, captured, receipt_started_ns
        )
    finally:
        os.close(descriptor)
    try:
        after_declared = declared.lstat()
        after_artifact = declared.resolve(strict=True)
        after_artifact.relative_to(target_root)
    except (FileNotFoundError, OSError, RuntimeError, ValueError):
        boundary_failure(
            receipt,
            "artifact",
            "artifact-post-confinement",
            timeout_seconds,
            captured,
            receipt_started_ns,
        )
    after_declared_identity = (
        after_declared.st_size,
        after_declared.st_dev,
        after_declared.st_ino,
        after_declared.st_mode,
    )
    if (
        after_open_identity != declared_identity
        or after_declared_identity != declared_identity
        or after_artifact != artifact
        or length != declared_metadata.st_size
    ):
        boundary_failure(
            receipt, "artifact", "artifact-changed", timeout_seconds, captured, receipt_started_ns
        )
    return (
        declared_metadata.st_size,
        digest.hexdigest(),
        declared_metadata.st_dev,
        declared_metadata.st_ino,
        declared_metadata.st_mode,
    )

def seed_component_failure(
    receipt, component, timeout_seconds, captured=b"", receipt_started_ns=None
):
    boundary_failure(
        receipt,
        "artifact",
        f"seed-{component}",
        timeout_seconds,
        captured,
        receipt_started_ns,
    )

def build_boundary(receipt, arguments, timeout_seconds=boundary_timeout_seconds, expected_fresh=None, expected_seed=None):
    receipt_started_ns = time.monotonic_ns()
    return_code, captured = run_boundary_command(
        receipt, arguments, timeout_seconds, receipt_started_ns
    )

    def fail(phase, reason):
        boundary_failure(
            receipt, phase, reason, timeout_seconds, captured, receipt_started_ns
        )

    if return_code != 0:
        fail("compile", f"exit-{return_code}")
    records = []
    for line in captured.splitlines():
        try:
            text = line.decode("utf-8")
        except UnicodeDecodeError:
            fail("json", "non-utf8-output")
        stripped = text.strip()
        if not stripped:
            continue
        try:
            value = json.loads(stripped)
        except json.JSONDecodeError:
            if stripped.startswith(("{", "[")):
                fail("json", "malformed-json")
            if not re.fullmatch(r"(?:Blocking waiting for file lock.*|Compiling\s+.*|Checking\s+.*|Finished\s+.*|Fresh\s+.*)", stripped):
                fail("json", "unexpected-non-json-output")
            continue
        if isinstance(value, dict):
            records.append(value)
        else:
            fail("json", "non-object-json")
    finished = [value for value in records if value.get("reason") == "build-finished"]
    if len(finished) != 1 or finished[0].get("success") is not True:
        fail("json", "build-finished")
    artifacts = []
    for value in records:
        cargo_target = value.get("target", {})
        profile = value.get("profile", {})
        if (
            value.get("reason") == "compiler-artifact"
            and cargo_target.get("name") == "swarm_governance_witness"
            and cargo_target.get("kind") == ["lib"]
            and profile.get("test") is False
        ):
            artifacts.append(value)
    if len(artifacts) != 1:
        fail("json", f"artifact-cardinality-{len(artifacts)}")
    artifact_record = artifacts[0]
    if expected_fresh is not None and artifact_record.get("fresh") is not expected_fresh:
        fail("json", "artifact-fresh")
    filenames = artifact_record.get("filenames")
    if not isinstance(filenames, list):
        fail("json", "artifact-filenames")
    rlibs = [value for value in filenames if isinstance(value, str) and value.endswith(".rlib")]
    if len(rlibs) != 1:
        fail("json", f"rlib-cardinality-{len(rlibs)}")
    declared = pathlib.Path(rlibs[0])
    if not declared.is_absolute():
        declared = exact_root / declared
    try:
        declared_metadata = declared.lstat()
    except (FileNotFoundError, OSError):
        fail("artifact", "artifact-declared-type")
    if (
        not stat.S_ISREG(declared_metadata.st_mode)
        or stat.S_ISLNK(declared_metadata.st_mode)
        or declared_metadata.st_size <= 0
    ):
        fail("artifact", "artifact-declared-type")
    try:
        target_root = target.resolve(strict=True)
        artifact = declared.resolve(strict=True)
        artifact.relative_to(target_root)
    except (FileNotFoundError, RuntimeError, ValueError):
        fail("artifact", "artifact-confinement")
    before = boundary_artifact_snapshot(
        receipt,
        declared,
        declared_metadata,
        target_root,
        artifact,
        timeout_seconds,
        captured,
        receipt_started_ns,
    )
    try:
        repeat_metadata = declared.lstat()
    except (FileNotFoundError, OSError):
        fail("artifact", "artifact-repeat-type")
    after = boundary_artifact_snapshot(
        receipt,
        declared,
        repeat_metadata,
        target_root,
        artifact,
        timeout_seconds,
        captured,
        receipt_started_ns,
    )
    if after != before:
        fail("artifact", "artifact-unstable")
    elapsed_ms = (time.monotonic_ns() - receipt_started_ns) // 1_000_000
    result = {
        "artifact": artifact,
        "declared": declared,
        "snapshot": before,
        "elapsed_ms": elapsed_ms,
        "started_ns": receipt_started_ns,
    }
    if expected_seed is not None:
        seed_snapshot = expected_seed["snapshot"]
        if declared != expected_seed["declared"]:
            seed_component_failure(
                receipt, "declared-path", timeout_seconds, captured, receipt_started_ns
            )
        if artifact != expected_seed["artifact"]:
            seed_component_failure(
                receipt, "resolved-path", timeout_seconds, captured, receipt_started_ns
            )
        if before[0] != seed_snapshot[0]:
            seed_component_failure(
                receipt, "length", timeout_seconds, captured, receipt_started_ns
            )
        if before[1] != seed_snapshot[1]:
            seed_component_failure(
                receipt, "sha256", timeout_seconds, captured, receipt_started_ns
            )
        if before[2] != seed_snapshot[2]:
            seed_component_failure(
                receipt, "device", timeout_seconds, captured, receipt_started_ns
            )
        if before[4] != seed_snapshot[4]:
            seed_component_failure(
                receipt, "mode", timeout_seconds, captured, receipt_started_ns
            )
        result["inode_relation"] = "stable" if before[3] == seed_snapshot[3] else "replaced"
    print(
        f"deadline_boundary_progress receipt={receipt} phase=artifact state=passed "
        f"timeout_seconds={timeout_seconds} reason=validated elapsed_ms={elapsed_ms}",
        flush=True,
    )
    return result

def open_retained_seed_descriptor(receipt, seed, timeout_seconds, receipt_started_ns):
    declared = seed["declared"]
    try:
        metadata = declared.lstat()
        target_root = target.resolve(strict=True)
        artifact = declared.resolve(strict=True)
        artifact.relative_to(target_root)
    except (FileNotFoundError, OSError, RuntimeError, ValueError):
        seed_component_failure(
            receipt, "retained-path", timeout_seconds, receipt_started_ns=receipt_started_ns
        )
    if artifact != seed["artifact"]:
        seed_component_failure(
            receipt,
            "retained-resolved-path",
            timeout_seconds,
            receipt_started_ns=receipt_started_ns,
        )
    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        seed_component_failure(
            receipt, "retained-type", timeout_seconds, receipt_started_ns=receipt_started_ns
        )
    try:
        return os.open(declared, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError:
        seed_component_failure(
            receipt, "retained-open", timeout_seconds, receipt_started_ns=receipt_started_ns
        )

def revalidate_retained_seed(
    receipt, seed, descriptor, timeout_seconds, receipt_started_ns
):
    expected = seed["snapshot"]
    try:
        before = os.fstat(descriptor)
    except OSError:
        seed_component_failure(
            receipt, "retained-fstat", timeout_seconds, receipt_started_ns=receipt_started_ns
        )
    if not stat.S_ISREG(before.st_mode) or before.st_size <= 0:
        seed_component_failure(
            receipt, "retained-type", timeout_seconds, receipt_started_ns=receipt_started_ns
        )
    if before.st_size != expected[0]:
        seed_component_failure(
            receipt, "retained-length", timeout_seconds, receipt_started_ns=receipt_started_ns
        )
    if before.st_dev != expected[2]:
        seed_component_failure(
            receipt, "retained-device", timeout_seconds, receipt_started_ns=receipt_started_ns
        )
    if before.st_ino != expected[3]:
        seed_component_failure(
            receipt, "retained-inode", timeout_seconds, receipt_started_ns=receipt_started_ns
        )
    if before.st_mode != expected[4]:
        seed_component_failure(
            receipt, "retained-mode", timeout_seconds, receipt_started_ns=receipt_started_ns
        )
    digest = hashlib.sha256()
    length = 0
    try:
        os.lseek(descriptor, 0, os.SEEK_SET)
        while True:
            chunk = os.read(descriptor, 1_048_576)
            if not chunk:
                break
            digest.update(chunk)
            length += len(chunk)
        after = os.fstat(descriptor)
    except OSError:
        seed_component_failure(
            receipt, "retained-read", timeout_seconds, receipt_started_ns=receipt_started_ns
        )
    before_identity = (before.st_size, before.st_dev, before.st_ino, before.st_mode)
    after_identity = (after.st_size, after.st_dev, after.st_ino, after.st_mode)
    if after_identity != before_identity:
        seed_component_failure(
            receipt, "retained-changed", timeout_seconds, receipt_started_ns=receipt_started_ns
        )
    if length != expected[0]:
        seed_component_failure(
            receipt,
            "retained-read-length",
            timeout_seconds,
            receipt_started_ns=receipt_started_ns,
        )
    if digest.hexdigest() != expected[1]:
        seed_component_failure(
            receipt, "retained-sha256", timeout_seconds, receipt_started_ns=receipt_started_ns
        )

debug_build_modes = [
    ("non_test_default_debug", ["build", "-p", "swarm-governance-witness", "--lib", "--locked", "--offline"]),
    ("non_test_all_features_debug", ["build", "-p", "swarm-governance-witness", "--lib", "--all-features", "--locked", "--offline"]),
]
for receipt, arguments in debug_build_modes:
    result = build_boundary(receipt, arguments)
    print(f"deadline_boundary receipt={receipt} tree={tree} token={token} status=passed artifact_sha256={result['snapshot'][1]}")

default_release_arguments = ["build", "-p", "swarm-governance-witness", "--lib", "--release", "--locked", "--offline"]
seed = build_boundary(
    "cold_default_release_seed",
    default_release_arguments,
    timeout_seconds=boundary_seed_timeout_seconds,
    expected_fresh=False,
)

def run_seed_bound_checks(seed, seed_descriptor):
    release_build_modes = [
        ("non_test_default_release", default_release_arguments),
        ("non_test_all_features_release", ["build", "-p", "swarm-governance-witness", "--lib", "--release", "--all-features", "--locked", "--offline"]),
    ]
    for receipt, arguments in release_build_modes:
        result = build_boundary(receipt, arguments, expected_fresh=True, expected_seed=seed)
        revalidate_retained_seed(
            receipt,
            seed,
            seed_descriptor,
            boundary_timeout_seconds,
            result["started_ns"],
        )
        print(
            f"deadline_boundary receipt={receipt} tree={tree} token={token} status=passed "
            f"artifact_sha256={result['snapshot'][1]} seed_artifact_sha256={seed['snapshot'][1]} "
            f"seed_inode={seed['snapshot'][3]} published_inode={result['snapshot'][3]} "
            f"inode_relation={result['inode_relation']}"
        )

    downstream = scratch / "deadline-downstream"
    (downstream / "src").mkdir(parents=True)
    (downstream / "Cargo.toml").write_text(
        "[package]\nname=\"phase285-a1-boundary\"\nversion=\"0.0.0\"\nedition=\"2024\"\n"
        + "[dependencies]\nswarm-governance-witness={path=" + json.dumps(str(exact_root / "crates/swarm-governance-witness")) + "}\n"
    )
    main = downstream / "src/main.rs"
    main.write_text(
        "use swarm_governance_witness::{PublicWitnessServiceConfigV1,store_proxy_subjects};\n"
        "fn main(){let _=store_proxy_subjects();let _:Option<PublicWitnessServiceConfigV1>=None;}\n"
    )
    lock = cargo(["generate-lockfile", "--offline", "--manifest-path", str(downstream / "Cargo.toml")], downstream)
    if lock.returncode != 0:
        raise SystemExit(f"deadline downstream lock generation failed:\n{lock.stdout}")
    positive = cargo(["check", "--manifest-path", str(downstream / "Cargo.toml"), "--locked", "--offline"], downstream)
    if positive.returncode != 0:
        raise SystemExit(f"deadline downstream positive failed:\n{positive.stdout}")
    print(f"deadline_boundary receipt=downstream_public_api_positive tree={tree} token={token} status=passed")

    negative_probes = [
        ("downstream_public_start_inner_private", "use swarm_governance_witness::{NatsPublicWitnessStoreProxyClient,PublicWitnessServiceRunner};fn main(){let _=PublicWitnessServiceRunner::<NatsPublicWitnessStoreProxyClient>::start_inner;}", "E0624", "start_inner"),
        ("downstream_private_start_inner_private", "use swarm_governance_witness::{NatsWitnessStore,StoreProxyServiceRunner};fn main(){let _=StoreProxyServiceRunner::<NatsWitnessStore>::start_inner;}", "E0624", "start_inner"),
        ("downstream_observer_noop_private", "use swarm_governance_witness::service_config::{SubscriberAdmissionObserverV1,NoopSubscriberAdmissionObserverV1};fn main(){}", "E0603", "service_config"),
        ("downstream_test_builder_absent", "use swarm_governance_witness::{PublicWitnessDispatcher,PublicWitnessStoreProxyClient};fn probe<C:PublicWitnessStoreProxyClient>(d:&mut PublicWitnessDispatcher<C>){d.observe_subscriber_admissions_for_test(todo!());}fn main(){}", "E0599", "observe_subscriber_admissions_for_test"),
    ]
    for receipt, source, code, symbol in negative_probes:
        main.write_text(source + "\n")
        result = cargo(["check", "--manifest-path", str(downstream / "Cargo.toml"), "--locked", "--offline"], downstream)
        if result.returncode == 0 or code not in result.stdout or symbol not in result.stdout:
            raise SystemExit(f"deadline {receipt} did not fail at intended API boundary:\n{result.stdout}")
        print(f"deadline_boundary receipt={receipt} tree={tree} token={token} diagnostic={code} symbol={symbol} status=passed")

    pre_symbol_started_ns = time.monotonic_ns()
    revalidate_retained_seed(
        "pre_symbol_scan",
        seed,
        seed_descriptor,
        boundary_timeout_seconds,
        pre_symbol_started_ns,
    )
    artifact_candidates = list((target / "debug").glob("libswarm_governance_witness*.rlib")) + list((target / "release").glob("libswarm_governance_witness*.rlib"))
    if len(artifact_candidates) < 2:
        raise SystemExit("deadline non-test artifacts absent")
    for artifact in artifact_candidates:
        raw = artifact.read_bytes()
        for symbol in [b"RecordingWorkerTransitionObserverV1", b"RecordingSubscriberAdmissionObserverV1", b"DeadlineGateV1", b"deadline_state_machine_is_receipt_anchored_and_mutation_sensitive", b"subscriber_callsite_is_receipt_anchored_and_mutation_sensitive", b"observe_worker_transitions_for_test", b"observe_subscriber_admissions_for_test"]:
            if symbol in raw:
                raise SystemExit(f"deadline test-only symbol present in non-test artifact: {symbol.decode()}")
    print(f"deadline_boundary receipt=non_test_recorder_symbols_absent tree={tree} token={token} artifacts={len(artifact_candidates)} status=passed")

seed_descriptor = None
try:
    seed_descriptor = open_retained_seed_descriptor(
        "cold_default_release_seed",
        seed,
        boundary_seed_timeout_seconds,
        seed["started_ns"],
    )
    revalidate_retained_seed(
        "cold_default_release_seed",
        seed,
        seed_descriptor,
        boundary_seed_timeout_seconds,
        seed["started_ns"],
    )
    seed["elapsed_ms"] = (time.monotonic_ns() - seed["started_ns"]) // 1_000_000
    print(
        f"deadline_boundary receipt=cold_default_release_seed tree={tree} token={token} status=passed "
        f"elapsed_ms={seed['elapsed_ms']} artifact_sha256={seed['snapshot'][1]}"
    )
    run_seed_bound_checks(seed, seed_descriptor)
finally:
    if seed_descriptor is not None:
        os.close(seed_descriptor)

mutant_paths = {
    "config": exact_root / "crates/swarm-governance-witness/src/service_config.rs",
    "private": exact_root / "crates/swarm-governance-witness/src/store_proxy_service.rs",
    "public": exact_root / "crates/swarm-governance-witness/src/public_dispatcher.rs",
    "library": exact_root / "crates/swarm-governance-witness/src/lib.rs",
    "fixture": exact_root / "crates/swarm-governance-witness/tests/full_service_path.rs",
}
originals = {name: path.read_text() for name, path in mutant_paths.items()}

retry_old = "        let response = self.proxy.compare_and_swap(request).await;\n        let cas_applied ="
retry_new = """        let retry_request = request.clone();
        let response = self.proxy.compare_and_swap(request).await;
        self.worker_observer
            .observe(WorkerTransitionEventV1::ProxyStoreBegin {
                worker: WorkerKindV1::Public,
                operation: \"compare_and_swap\",
                cas_attempted: true,
            });
        let _retry_response = self.proxy.compare_and_swap(retry_request).await;
        let cas_applied ="""

mutation_specs = [
    ("receipt_reset", "private", "        message.receipt_deadline,", "        ReceiptDeadlineV1::private(),", 2, 2, "deadline_r20_private_queue_expired"),
    ("queue_check_deletion", "config", "    if transition.dequeued().is_err() {\n        return;\n    }\n", "", 1, 1, "deadline_r20_private_queue_expired"),
    ("preflight_check_deletion", "private", "        if receipt_deadline.ensure_open().is_err() {\n            return Err(StoreProxyServiceErrorV1::Timeout);\n        }\n", "", 1, 1, "deadline_r20_preflight_check_deleted"),
    ("pre_store_check_deletion", "config", "        self.deadline.ensure_open()?;\n        self.observer", "        self.observer", 1, 1, "private store event diverged from recording WitnessAtomicStore"),
    ("relative_timeout", "config", "timeout_at(self.at, future)", "tokio::time::timeout(Duration::from_millis(STORE_HANDLER_DEADLINE_MILLIS), future)", 1, 1, "deadline_r20_post_cas_exact_store_trace"),
    ("late_response_enqueue", "config", "    if transition.response_deadline_check().is_err() {\n        return;\n    }\n    transition.publish(publisher, reply, bytes).await;", "    let _ = transition.response_deadline_check();\n    transition.publish(publisher, reply, bytes).await;", 1, 1, "deadline_r20_private_response_enqueue_expired"),
    ("retry", "public", retry_old, retry_new, 1, 1, "deadline_r20_post_cas_exact_store_trace"),
    ("cas_ambiguity_downgrade", "public", "                transition.outcome_unknown();\n", "", 3, 1, "deadline_r20_public_private_exchange_crosses_deadline_behavior"),
    ("fabricated_counter", "library", "WorkerTransitionEventV1::CasAppliedObservation { .. } => cas_applied += 1,", "WorkerTransitionEventV1::CasAppliedObservation { .. } => cas_applied += 0,", 1, 1, "CAS-applied event diverged from recording WitnessAtomicStore"),
    ("helper_bypass", "private", "__CUSTOM_HELPER_BYPASS__", "", 0, 0, "deadline_r20_private_queue_expired"),
    ("worker_budget_substitution", "config", "Self::from_now(STORE_HANDLER_DEADLINE_MILLIS)", "Self::from_now(STORE_HANDLER_DEADLINE_MILLIS + 1)", 1, 1, "deadline_r20_worker_budget_substitution"),
    ("private_deadline_reset_after_dequeue", "private", "    run_private_worker_message(service, message, observer, publisher).await;", "    let message = PrivateIngressMessage { receipt_deadline: ReceiptDeadlineV1::private(), ..message };\n    run_private_worker_message(service, message, observer, publisher).await;", 1, 1, "deadline_r20_private_queue_expired_behavior"),
    ("public_deadline_reset_after_dequeue", "public", "    run_public_worker_message(dispatcher, message, observer, publisher).await;", "    let message = PublicIngressMessage { receipt_deadline: ReceiptDeadlineV1::public(), ..message };\n    run_public_worker_message(dispatcher, message, observer, publisher).await;", 1, 1, "deadline_r20_public_queue_expired_behavior"),
    ("private_subscriber_capture_reset", "private", "        receipt_deadline,\n    };\n    if ingress.try_send", "        receipt_deadline: ReceiptDeadlineV1::from_now(STORE_HANDLER_DEADLINE_MILLIS + 1),\n    };\n    if ingress.try_send", 1, 1, "deadline_r20_private_queue_expired_behavior"),
    ("public_subscriber_capture_reset", "public", "        receipt_deadline,\n    };\n    if !try_enqueue_public_message", "        receipt_deadline: ReceiptDeadlineV1::from_now(PUBLIC_HANDLER_DEADLINE_MILLIS + 1),\n    };\n    if !try_enqueue_public_message", 1, 1, "deadline_r20_public_queue_expired_behavior"),
    ("private_subscriber_capture_after_queue", "private", "if ingress.try_send(ingress_message).is_err() {", "if ingress.try_send(PrivateIngressMessage { receipt_deadline: ReceiptDeadlineV1::from_now(STORE_HANDLER_DEADLINE_MILLIS + 2), ..ingress_message }).is_err() {", 1, 1, "deadline_r20_private_queue_expired_behavior"),
    ("public_subscriber_capture_after_queue", "public", "if !try_enqueue_public_message(ingress, ingress_message) {", "if !try_enqueue_public_message(ingress, PublicIngressMessage { receipt_deadline: ReceiptDeadlineV1::from_now(PUBLIC_HANDLER_DEADLINE_MILLIS + 2), ..ingress_message }) {", 1, 1, "deadline_r20_public_queue_expired_behavior"),
    ("private_subscriber_overlong_deadline", "private", "let receipt_deadline = ReceiptDeadlineV1::private();", "let receipt_deadline = ReceiptDeadlineV1::from_now(STORE_HANDLER_DEADLINE_MILLIS + 1_000);", 1, 1, "deadline_r20_private_queue_expired_behavior"),
    ("public_subscriber_overlong_deadline", "public", "let receipt_deadline = ReceiptDeadlineV1::public();", "let receipt_deadline = ReceiptDeadlineV1::from_now(PUBLIC_HANDLER_DEADLINE_MILLIS + 1_000);", 1, 1, "deadline_r20_public_queue_expired_behavior"),
]

def mutate_source(label, name, old, new, expected_count, replace_count):
    text = originals[name]
    if label == "helper_bypass":
        start = text.index("pub(crate) async fn run_private_worker_message")
        body_start = text.index(") {", start) + 3
        end = text.index("\npub(crate) async fn receive_and_run_private_worker_message", body_start)
        body = """
    let _ = service
        .handle_subject_bytes_before(
            &message.subject,
            &message.payload,
            message.receipt_deadline,
            observer,
        )
        .await;
    let _ = publisher;
}"""
        return text[:body_start] + body + text[end:]
    if text.count(old) != expected_count:
        raise SystemExit(f"deadline executable mutation anchor differs: {label} count={text.count(old)}")
    return text.replace(old, new, replace_count)

mutation_digests = set()
if len(mutation_specs) != 19:
    raise SystemExit("deadline first-FQN mutation inventory differs")
for label, name, old, new, expected_count, replace_count, expected_failure in mutation_specs:
    for source_name, path in mutant_paths.items():
        path.write_text(originals[source_name])
    candidate = mutate_source(label, name, old, new, expected_count, replace_count)
    mutant_paths[name].write_text(candidate)
    digest = hashlib.sha256(b"\0".join(mutant_paths[key].read_bytes() for key in sorted(mutant_paths))).hexdigest()
    if digest in mutation_digests:
        raise SystemExit(f"deadline executable mutation digest duplicated: {label}")
    mutation_digests.add(digest)
    try:
        result = cargo([
            "test", "-p", "swarm-governance-witness", "--lib", "--locked", "--offline",
            "deadline_state_machine_tests::deadline_state_machine_is_receipt_anchored_and_mutation_sensitive",
            "--", "--exact", "--test-threads=1",
        ])
    except subprocess.TimeoutExpired as error:
        raise SystemExit(
            f"deadline executable mutation timed out instead of failing its intended assertion: {label}\n"
            + ((error.stdout or b"").decode(errors="replace") if isinstance(error.stdout, bytes) else (error.stdout or ""))
        ) from error
    output = result.stdout
    if result.returncode == 0 or "running 1 test" not in output or "0 passed; 1 failed; 0 ignored" not in output or expected_failure not in output:
        raise SystemExit(f"deadline executable mutation did not fail at intended assertion: {label}\n{output}")
    print(f"deadline_executable_mutation mutation={label} tree={tree} token={token} compiled=1 mutation_executed=1 mutation_failed=1 intended={expected_failure} source_sha256={digest}")

callsite_mutations = [
    ("private_inline_helper_bypass", "private", "__INLINE_PRIVATE_INGRESS__", "", 0, 0, "deadline_r24_private_late_first_response"),
    ("public_inline_helper_bypass", "public", "__INLINE_PUBLIC_INGRESS__", "", 0, 0, "deadline_r24_public_second_response"),
    ("drop_before_enqueue", "private", "if ingress.try_send(ingress_message).is_err() {", "if { let _ = ingress_message; true } {", 1, 1, "private request one did not enter store: Elapsed(())"),
    ("fabricated_receipt", "private", "if ingress.try_send(ingress_message).is_err() {\n        return Some(Err((reply, payload)));\n    }\n    admission_observer.accepted(receipt);\n    Some(Ok(()))", "let _ = (ingress, ingress_message);\n    admission_observer.accepted(receipt);\n    Some(Ok(()))", 1, 1, "private request one did not enter store: Elapsed(())"),
    ("post_accept_refreshed_capture", "private", "        receipt_deadline,\n    };\n    if ingress.try_send", "        receipt_deadline: ReceiptDeadlineV1::from_now(STORE_HANDLER_DEADLINE_MILLIS + 2_000),\n    };\n    if ingress.try_send", 1, 1, "deadline_r24_private_late_first_response"),
    ("public_start_delegation_bypass", "public", "        Self::start_inner(client, dispatcher).await", "        let _ = dispatcher;\n        Ok(Self { tasks: Vec::new(), client: Some(client), ready: Arc::new(AtomicBool::new(true)), stop_result: None, _proxy: PhantomData })", 1, 1, "public receipt one absent"),
    ("private_start_delegation_bypass", "private", "        Self::start_inner(connection, service).await", "        let client = connection.client;\n        let _ = service;\n        Ok(Self { tasks: Vec::new(), client: Some(client), ready: Arc::new(AtomicBool::new(true)), stop_result: None, _service: std::marker::PhantomData })", 1, 1, "private request one did not enter store: Elapsed(())"),
]
if len(callsite_mutations) != 7:
    raise SystemExit("deadline callsite mutation inventory differs")

callsite_panic_header = re.compile(r"^thread '([^']+)'(?: \([0-9]+\))? panicked at .+:$")
callsite_test_thread = "deadline_state_machine_tests::subscriber_callsite_is_receipt_anchored_and_mutation_sensitive"
lib_test_inventory = []
for line in pathlib.Path(list_path).read_text().splitlines():
    match = re.fullmatch(r"([^:]+(?:::[^:]+)*): test", line)
    if match:
        lib_test_inventory.append(match.group(1))
if (
    len(lib_test_inventory) != len(set(lib_test_inventory))
    or lib_test_inventory.count(callsite_test_thread) != 1
):
    raise SystemExit("deadline callsite compiled test inventory differs")
expected_callsite_filtered = str(len(lib_test_inventory) - 1)

def callsite_panic_records(output):
    records = []
    lines = output.splitlines()
    for index, line in enumerate(lines):
        header = callsite_panic_header.fullmatch(line)
        if header is None:
            continue
        message = None
        for following in lines[index + 1:]:
            if callsite_panic_header.fullmatch(following):
                break
            if following.strip():
                message = following
                break
        if message is None:
            return None
        records.append((header.group(1), message))
    return records

def callsite_failure_oracle(output, expected_failure):
    return (
        callsite_panic_records(output) == [
            ("phase285-a1-subscriber-callsite", expected_failure),
            (callsite_test_thread, "subscriber thread panicked: Any { .. }"),
        ]
        and output.count(expected_failure) == 1
    )

oracle_control_count = 0
oracle_timeout_abbreviated_count = 0
for oracle_label, _, _, _, _, _, oracle_message in callsite_mutations:
    oracle_canonical = f"""thread 'phase285-a1-subscriber-callsite' panicked at src/lib.rs:1:
{oracle_message}
thread '{callsite_test_thread}' panicked at src/lib.rs:2:
subscriber thread panicked: Any {{ .. }}
"""
    oracle_appended = oracle_canonical.replace(oracle_message, "different_first_relation", 1) + oracle_message + "\n"
    oracle_swapped = f"""thread '{callsite_test_thread}' panicked at src/lib.rs:2:
subscriber thread panicked: Any {{ .. }}
thread 'phase285-a1-subscriber-callsite' panicked at src/lib.rs:1:
{oracle_message}
"""
    oracle_extra = oracle_canonical + "thread 'collateral' panicked at src/lib.rs:3:\ncollateral relation\n"
    if (
        not callsite_failure_oracle(oracle_canonical, oracle_message)
        or callsite_failure_oracle(oracle_appended, oracle_message)
        or callsite_failure_oracle(oracle_swapped, oracle_message)
        or callsite_failure_oracle(oracle_extra, oracle_message)
    ):
        raise SystemExit(f"deadline callsite failure oracle self-test failed: {oracle_label}")
    oracle_control_count += 4
    timeout_suffix = ": Elapsed(())"
    if oracle_message.endswith(timeout_suffix):
        oracle_abbreviated = oracle_canonical.replace(
            oracle_message,
            oracle_message.removesuffix(timeout_suffix),
            1,
        )
        if callsite_failure_oracle(oracle_abbreviated, oracle_message):
            raise SystemExit(f"deadline callsite abbreviated timeout oracle passed: {oracle_label}")
        oracle_control_count += 1
        oracle_timeout_abbreviated_count += 1
if oracle_control_count != 31 or oracle_timeout_abbreviated_count != 3:
    raise SystemExit("deadline callsite failure oracle control inventory differs")
print("deadline_callsite_failure_oracle_self_test controls=31 canonical=7 timeout_abbreviated=3")

def mutate_callsite_source(label, name, old, new, expected_count, replace_count):
    text = originals[name]
    if label == "private_inline_helper_bypass":
        anchor = """                    if let Some(Err((reply, payload))) = admit_private_subscription_message(
                        subject,
                        message,
                        &sender,
                        admission_observer.as_ref(),
                        max_request_bytes,
                    ) && let Some(bytes) = service.overload_response(subject, &payload)
"""
        replacement = """                    let _unreachable_admission_helper = admit_private_subscription_message;
                    let inline_result = match message.reply {
                        Some(reply)
                            if message.subject.as_str() == subject
                                && message.payload.len() <= max_request_bytes
                                && bounded_inbox(&reply) =>
                        {
                            let payload = message.payload.to_vec();
            let receipt_deadline = ReceiptDeadlineV1::from_now(
                STORE_HANDLER_DEADLINE_MILLIS + 1_000,
            );
            let receipt = SubscriberAdmissionReceiptV1 {
                worker: WorkerKindV1::Private,
                subject: subject.to_string(),
                payload_sha256: swarm_crypto::sha256_hex(&payload),
                payload: payload.clone(),
                deadline_identity: receipt_deadline.identity_for_test(),
                reply: reply.to_string(),
                deadline_millis: STORE_HANDLER_DEADLINE_MILLIS,
            };
            let ingress_message = PrivateIngressMessage {
                subject: subject.to_string(),
                payload: payload.clone(),
                reply: reply.clone(),
                receipt_deadline,
                            };
                            if sender.try_send(ingress_message).is_err() {
                                Some(Err((reply, payload)))
                            } else {
                                admission_observer.accepted(receipt);
                                Some(Ok(()))
                            }
                        }
                        _ => None,
                    };
                    if let Some(Err((reply, payload))) = inline_result
                        && let Some(bytes) = service.overload_response(subject, &payload)
"""
        if text.count(anchor) != 1:
            raise SystemExit(f"deadline callsite mutation anchor differs: {label} count={text.count(anchor)}")
        return text.replace(anchor, replacement, 1)
    if label == "public_inline_helper_bypass":
        anchor = """            if !admit_public_subscription_message(
                expected_subject,
                message,
                &ingress,
                admission_observer.as_ref(),
                max_request_bytes,
            ) {
                // The bounded queue refusal happens synchronously here,
                // before a worker task, dispatcher, or store call can begin.
                continue;
            }
"""
        replacement = """            let _unreachable_admission_helper = admit_public_subscription_message;
            if message.subject.as_str() != expected_subject
                || message.payload.len() > max_request_bytes
            {
                continue;
            }
            let Some(reply) = message.reply else {
                continue;
            };
            if !is_bounded_inbox_reply(&reply) {
                continue;
            }
            let payload = message.payload.to_vec();
            let receipt_deadline = ReceiptDeadlineV1::from_now(
                PUBLIC_HANDLER_DEADLINE_MILLIS + 1_000,
            );
            let receipt = SubscriberAdmissionReceiptV1 {
                worker: WorkerKindV1::Public,
                subject: expected_subject.to_string(),
                payload_sha256: sha256_hex(&payload),
                payload: payload.clone(),
                deadline_identity: receipt_deadline.identity_for_test(),
                reply: reply.to_string(),
                deadline_millis: PUBLIC_HANDLER_DEADLINE_MILLIS,
            };
            let ingress_message = PublicIngressMessage {
                subject: expected_subject.to_string(),
                payload,
                reply,
                receipt_deadline,
            };
            if !try_enqueue_public_message(&ingress, ingress_message) {
                continue;
            }
            admission_observer.accepted(receipt);
"""
        if text.count(anchor) != 1:
            raise SystemExit(f"deadline callsite mutation anchor differs: {label} count={text.count(anchor)}")
        return text.replace(anchor, replacement, 1)
    if text.count(old) != expected_count:
        raise SystemExit(f"deadline callsite mutation anchor differs: {label} count={text.count(old)}")
    return text.replace(old, new, replace_count)

for label, name, old, new, expected_count, replace_count, expected_failure in callsite_mutations:
    for source_name, path in mutant_paths.items():
        path.write_text(originals[source_name])
    mutant_paths[name].write_text(
        mutate_callsite_source(label, name, old, new, expected_count, replace_count)
    )
    digest = hashlib.sha256(b"\0".join(mutant_paths[key].read_bytes() for key in sorted(mutant_paths))).hexdigest()
    if digest in mutation_digests:
        raise SystemExit(f"deadline callsite mutation digest duplicated: {label}")
    mutation_digests.add(digest)
    receipt_path = scratch / f"callsite-mutant-{label}.json"
    try:
        result = cargo([
            "test", "-p", "swarm-governance-witness", "--lib", "--locked", "--offline",
            "deadline_state_machine_tests::subscriber_callsite_is_receipt_anchored_and_mutation_sensitive",
            "--", "--ignored", "--exact", "--test-threads=1",
        ], extra_environment={
            "PHASE285_DEADLINE_CALLSITE_RECEIPT": str(receipt_path),
            "PHASE285_DEADLINE_TREE": tree,
            "PHASE285_DEADLINE_INVOCATION_TOKEN": token,
            "PHASE285_DEADLINE_CASE": "service_checkpoint_deadline",
        })
    except subprocess.TimeoutExpired as error:
        raise SystemExit(
            f"deadline callsite mutation timed out instead of failing its intended assertion: {label}\n"
            + ((error.stdout or b"").decode(errors="replace") if isinstance(error.stdout, bytes) else (error.stdout or ""))
        ) from error
    output = result.stdout
    running = re.findall(r"^running (\d+) test$", output, re.M)
    summaries = re.findall(
        r"^test result: FAILED\. 0 passed; 1 failed; 0 ignored; 0 measured; (\d+) filtered out; finished in .+$",
        output,
        re.M,
    )
    test_lines = re.findall(
        r"^test deadline_state_machine_tests::subscriber_callsite_is_receipt_anchored_and_mutation_sensitive \.\.\. FAILED$",
        output,
        re.M,
    )
    if (
        result.returncode != 101
        or running != ["1"]
        or summaries != [expected_callsite_filtered]
        or len(test_lines) != 1
        or not callsite_failure_oracle(output, expected_failure)
        or receipt_path.exists()
    ):
        raise SystemExit(f"deadline callsite mutation did not fail at intended assertion: {label}\n{output}")
    print(f"deadline_callsite_mutation mutation={label} tree={tree} token={token} compiled=1 mutation_executed=1 mutation_failed=1 intended={expected_failure} source_sha256={digest}")

constructor_mutations = [
    ("constructor_predicate_substitution", "private", "request_deadline_millis != STORE_RESPONSE_GRANT_MILLIS", "request_deadline_millis == 0", 1, 1, "deadline_r24_constructor_results"),
    ("constructor_oracle_omission", "fixture", "    write_constructor_deadline_receipt(&observations)\n}", "    Err(ProtocolError::WitnessOutcomeMismatch)\n}", 1, 1, "WitnessOutcomeMismatch"),
    ("constructor_result_fabrication", "fixture", "result: if result.is_ok() {", "result: if false {", 1, 1, "deadline_r24_constructor_results"),
    ("constructor_delegation_deletion", "fixture", "        let result = NatsPublicWitnessStoreProxyClient::new(\n", "        let result: Result<NatsPublicWitnessStoreProxyClient, PublicWitnessProxyTransportErrorV1> = Err(PublicWitnessProxyTransportErrorV1::Framing);\n        let _ = (\n", 1, 1, "deadline_r24_constructor_results"),
    ("constructor_alternate_predicate", "private", "request_deadline_millis != STORE_RESPONSE_GRANT_MILLIS", "request_deadline_millis < STORE_RESPONSE_GRANT_MILLIS", 1, 1, "deadline_r24_constructor_results"),
]
if len(constructor_mutations) != 5:
    raise SystemExit("deadline constructor mutation inventory differs")
for label, name, old, new, expected_count, replace_count, expected_failure in constructor_mutations:
    for source_name, path in mutant_paths.items():
        path.write_text(originals[source_name])
    text = originals[name]
    if text.count(old) != expected_count:
        raise SystemExit(f"deadline constructor mutation anchor differs: {label} count={text.count(old)}")
    mutant_paths[name].write_text(text.replace(old, new, replace_count))
    digest = hashlib.sha256(b"\0".join(mutant_paths[key].read_bytes() for key in sorted(mutant_paths))).hexdigest()
    if digest in mutation_digests:
        raise SystemExit(f"deadline constructor mutation digest duplicated: {label}")
    mutation_digests.add(digest)
    receipt_path = scratch / f"constructor-mutant-{label}.json"
    try:
        result = cargo([
            "test", "-p", "swarm-governance-witness", "--test", "full_service_path", "--locked", "--offline",
            "full_service_path_constructor_deadline_is_exact_and_receipt_bound",
            "--", "--ignored", "--exact", "--test-threads=1",
        ], extra_environment={
            "PHASE285_DEADLINE_CONSTRUCTOR_RECEIPT": str(receipt_path),
            "PHASE285_DEADLINE_TREE": tree,
            "PHASE285_DEADLINE_INVOCATION_TOKEN": token,
            "PHASE285_DEADLINE_CASE": "service_checkpoint_deadline",
        })
    except subprocess.TimeoutExpired as error:
        raise SystemExit(
            f"deadline constructor mutation timed out instead of failing its intended assertion: {label}\n"
            + ((error.stdout or b"").decode(errors="replace") if isinstance(error.stdout, bytes) else (error.stdout or ""))
        ) from error
    output = result.stdout
    if result.returncode == 0 or "running 1 test" not in output or "0 passed; 1 failed; 0 ignored" not in output or expected_failure not in output:
        raise SystemExit(f"deadline constructor mutation did not fail at intended assertion: {label}\n{output}")
    print(f"deadline_constructor_mutation mutation={label} tree={tree} token={token} compiled=1 mutation_executed=1 mutation_failed=1 intended={expected_failure} source_sha256={digest}")

for source_name, path in mutant_paths.items():
    path.write_text(originals[source_name])
if len(mutation_digests) != 31:
    raise SystemExit(f"deadline unique source digest count differs: {len(mutation_digests)}")
print(f"deadline_focus rows=9 passed=9 failed=0 ignored=0 ledger_mutations={len(normalized_mutants)} first_fqn_mutations={len(mutation_specs)} callsite_mutations={len(callsite_mutations)} constructor_mutations={len(constructor_mutations)} unique_source_digests={len(mutation_digests)} boundary_receipts=10")
PY
  cleanup_temp_dir
  trap - EXIT
}

complete_receipt_artifact_snapshot() {
  local directory="$1" ledger="$2" receipt="$3" snapshot="$4" mode="$5"
  python3 -I - "$directory" "$ledger" "$receipt" "$snapshot" "$mode" <<'PY'
import hashlib, json, os, pathlib, stat, sys
directory, ledger, receipt, snapshot = map(pathlib.Path, sys.argv[1:5])
mode = sys.argv[5]
def reject(value): raise ValueError(value)
def canonical(value): return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
directory = directory.resolve(strict=True)
if ledger.parent.resolve(strict=True) != directory or receipt.parent.resolve(strict=True) != directory:
    raise SystemExit("complete_receipt_artifact[parent]")
if not ledger.exists() or not receipt.exists():
    raise SystemExit("complete_receipt_artifact[absent]")
expected_names = sorted([ledger.name, receipt.name] + ([snapshot.name] if snapshot.exists() else []))
if sorted(item.name for item in directory.iterdir()) != expected_names:
    raise SystemExit("complete_receipt_artifact[extra]")
parent = directory.stat()
records = {}
for name, path, maximum in (("ledger", ledger, 1048576), ("receipt", receipt, 2097152)):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or path.is_symlink() or stat.S_IMODE(info.st_mode) != 0o600:
        raise SystemExit(f"complete_receipt_artifact[{name}-type-mode]")
    raw = path.read_bytes()
    if not raw or len(raw) > maximum or raw.count(b"\n") != 1 or not raw.endswith(b"\n"):
        raise SystemExit(f"complete_receipt_artifact[{name}-framing-bound]")
    value = json.loads(raw[:-1], parse_constant=reject)
    if canonical(value) != raw[:-1]:
        raise SystemExit(f"complete_receipt_artifact[{name}-canonical]")
    records[name] = {"device":info.st_dev,"inode":info.st_ino,"size":info.st_size,"sha256":hashlib.sha256(raw).hexdigest()}
if records["ledger"]["device"] == records["receipt"]["device"] and records["ledger"]["inode"] == records["receipt"]["inode"]:
    raise SystemExit("complete_receipt_artifact[alias]")
ledger_raw = ledger.read_bytes()[:-1]
receipt_value = json.loads(receipt.read_bytes()[:-1], parse_constant=reject)
if bytes.fromhex(receipt_value.get("observation_ledger_canonical_hex", "")) != ledger_raw or receipt_value.get("observation_ledger_sha256") != hashlib.sha256(ledger_raw).hexdigest():
    raise SystemExit("complete_receipt_artifact[binding]")
record = {"parent_device":parent.st_dev,"parent_inode":parent.st_ino,"files":records}
if mode == "record":
    snapshot.write_bytes(canonical(record) + b"\n")
    os.chmod(snapshot, 0o600)
elif mode == "verify":
    expected = json.loads(snapshot.read_bytes(), parse_constant=reject)
    if expected != record:
        raise SystemExit("complete_receipt_artifact[handoff-mutated]")
else:
    raise SystemExit("complete_receipt_artifact[mode]")
print(f"complete_receipt_artifact mode={mode} ledger_bytes={records['ledger']['size']} receipt_bytes={records['receipt']['size']} passed=1")
PY
}

complete_receipt_artifact_hostile_controls() {
  local scratch="$1" source_ledger="$2" source_receipt="$3" root case_dir output
  root="$scratch/artifact-hostile"
  mkdir -m 700 "$root"
  expect_refusal() {
    local label="$1" expected="$2"
    shift 2
    output="$({ complete_receipt_artifact_snapshot "$@"; } 2>&1)" && {
      echo "complete receipt artifact mutation survived: $label" >&2
      return 1
    }
    [[ "$output" == *"$expected"* ]] || {
      echo "complete receipt artifact mutation reason differs: $label:$output" >&2
      return 1
    }
    echo "complete_receipt_artifact_mutation mutation=$label intended=$expected killed=1"
  }

  case_dir="$root/absent"; mkdir -m 700 "$case_dir"; cp "$source_ledger" "$case_dir/ledger.json"
  expect_refusal absent 'complete_receipt_artifact[absent]' "$case_dir" "$case_dir/ledger.json" "$case_dir/receipt.json" "$case_dir/snapshot.json" record

  case_dir="$root/precreated"; mkdir -m 700 "$case_dir"; : >"$case_dir/ledger.json"; chmod 600 "$case_dir/ledger.json"
  output="$root/precreated.txt"
  if PHASE285_COMPLETE_RECEIPT_LEDGER_PATH="$case_dir/ledger.json" \
    PHASE285_COMPLETE_RECEIPT_PATH="$case_dir/receipt.json" \
    PHASE285_COMPLETE_RECEIPT_INVOCATION_TOKEN="$(printf precreated | shasum -a 256 | awk '{print $1}')" \
    cargo test -p swarm-governance-witness --lib --locked --offline -- --test-threads=1 --ignored \
      service_checkpoint_relay_tests::complete_receipt_authority_and_grants_are_observed --exact >"$output" 2>&1; then
    echo "complete receipt precreated mutation survived" >&2; return 1
  fi
  grep -Fq 'complete receipt evidence is not fresh' "$output" || { cat "$output" >&2; return 1; }
  grep -Fq 'running 1 test' "$output" || { cat "$output" >&2; return 1; }
  echo 'complete_receipt_artifact_mutation mutation=precreated intended=fresh-path-refusal executed=1 killed=1'

  case_dir="$root/aliased"; mkdir -m 700 "$case_dir"; cp "$source_ledger" "$case_dir/ledger.json"; ln "$case_dir/ledger.json" "$case_dir/receipt.json"
  expect_refusal aliased 'complete_receipt_artifact[alias]' "$case_dir" "$case_dir/ledger.json" "$case_dir/receipt.json" "$case_dir/snapshot.json" record

  case_dir="$root/partial"; mkdir -m 700 "$case_dir"; cp "$source_ledger" "$case_dir/ledger.json"; cp "$source_receipt" "$case_dir/receipt.json"; truncate -s 32 "$case_dir/receipt.json"
  expect_refusal partial 'complete_receipt_artifact[receipt-framing-bound]' "$case_dir" "$case_dir/ledger.json" "$case_dir/receipt.json" "$case_dir/snapshot.json" record

  case_dir="$root/oversized"; mkdir -m 700 "$case_dir"; cp "$source_ledger" "$case_dir/ledger.json"; cp "$source_receipt" "$case_dir/receipt.json"; truncate -s 2097153 "$case_dir/receipt.json"
  expect_refusal oversized 'complete_receipt_artifact[receipt-framing-bound]' "$case_dir" "$case_dir/ledger.json" "$case_dir/receipt.json" "$case_dir/snapshot.json" record

  case_dir="$root/extra"; mkdir -m 700 "$case_dir"; cp "$source_ledger" "$case_dir/ledger.json"; cp "$source_receipt" "$case_dir/receipt.json"; : >"$case_dir/extra"
  expect_refusal extra 'complete_receipt_artifact[extra]' "$case_dir" "$case_dir/ledger.json" "$case_dir/receipt.json" "$case_dir/snapshot.json" record

  for label in replaced post_internal_mutated; do
    case_dir="$root/$label"; mkdir -m 700 "$case_dir"; cp "$source_ledger" "$case_dir/ledger.json"; cp "$source_receipt" "$case_dir/receipt.json"
    complete_receipt_artifact_snapshot "$case_dir" "$case_dir/ledger.json" "$case_dir/receipt.json" "$case_dir/snapshot.json" record >/dev/null
    if [ "$label" = replaced ]; then
      cp "$source_receipt" "$case_dir/replacement"; mv "$case_dir/replacement" "$case_dir/receipt.json"
    else
      printf ' ' >>"$case_dir/receipt.json"
    fi
    expect_refusal "$label" 'complete_receipt_artifact[' "$case_dir" "$case_dir/ledger.json" "$case_dir/receipt.json" "$case_dir/snapshot.json" verify
  done

  case_dir="$root/stale"; mkdir -m 700 "$case_dir"; cp "$source_ledger" "$case_dir/ledger.json"; cp "$source_receipt" "$case_dir/receipt.json"
  output="$case_dir/stale.txt"
  if PHASE285_COMPLETE_RECEIPT_LEDGER_PATH="$case_dir/ledger.json" PHASE285_COMPLETE_RECEIPT_PATH="$case_dir/receipt.json" \
    PHASE285_COMPLETE_RECEIPT_INVOCATION_TOKEN="$(printf stale | shasum -a 256 | awk '{print $1}')" \
    cargo test -p swarm-governance-witness --test service_checkpoint --locked --offline -- --test-threads=1 --ignored \
      complete_receipt_validation_precedes_suppression_and_failures_forward --exact >"$output" 2>&1; then
    echo "complete receipt stale identity mutation survived" >&2; return 1
  fi
  grep -Fq 'ledger identity' "$output" || { cat "$output" >&2; return 1; }
  grep -Fq 'running 1 test' "$output" || { cat "$output" >&2; return 1; }
  echo 'complete_receipt_artifact_mutation mutation=stale intended=ledger-identity killed=1'
  echo 'complete_receipt_artifact_self_test mutations=9 executed=2 killed=9 passed=1'
}

complete_receipt_source_guard() {
  local mode="${1:-normal}" library="$ROOT_DIR/crates/swarm-governance-witness/src/lib.rs"
  local external="$ROOT_DIR/crates/swarm-governance-witness/tests/service_checkpoint.rs"
  python3 -I - "$library" "$external" <<'PY'
import pathlib, sys
library, external = [pathlib.Path(path).read_text() for path in sys.argv[1:]]
start = library.index("fn validate_complete_receipt(")
end = library.index("\n}\n\n#[cfg(test)]\nmod service_checkpoint_observation_tests", start)
owned = library[start:end]
required = [
    '"PHASE285_COMPLETE_RECEIPT_LEDGER_PATH" | "PHASE285_COMPLETE_RECEIPT_PATH"',
    ".write(true)", ".create_new(true)", ".mode(0o600)", "file.sync_all()",
    "fn validate_complete_receipt(", "expected_invocation_token: &str",
    'return Err("current_invocation")', 'return Err("proxy_cross_copy")',
    "validate_complete_response_enqueue_attempts(",
    "if validate_complete_receipt(",
    "if sender.max_capacity() != 1", "match sender.try_send(receipt)",
    "run_worker_observation_test_async().await",
]
for fragment in required:
    if fragment not in owned: raise SystemExit(f"complete_receipt_source[missing:{fragment}]")
for fragment in ('return Err("response_enqueue_fabrication")', "fn validate_complete_response_enqueue_attempts("):
    if fragment not in library: raise SystemExit(f"complete_receipt_source[missing:{fragment}]")
for forbidden in ("std::process::Command", "with-nats-jetstream", "bash", "temp_dir()", "remove_file", "create_dir", "remove_dir"):
    if forbidden in owned: raise SystemExit(f"complete_receipt_source[forbidden:{forbidden}]")
if library.count("fn validate_complete_receipt(") != 1 or "pub fn validate_complete_receipt(" in library:
    raise SystemExit("complete_receipt_source[closed-validator]")
for fragment in ("fn independently_validate_artifacts(", "WitnessServiceResponseV1::decode_for_client_request", "WitnessStoreProxyRequestV1::decode", "WitnessStoreReadResultV1", "proxy cross-copy", "response enqueue fabrication", "PHASE285_COMPLETE_RECEIPT_LEDGER_PATH", "PHASE285_COMPLETE_RECEIPT_PATH"):
    if fragment not in external: raise SystemExit(f"complete_receipt_external[missing:{fragment}]")
for forbidden in ("run_complete_receipt_suppression_test", "validate_complete_receipt", "std::process::Command"):
    if forbidden in external: raise SystemExit(f"complete_receipt_external[forbidden:{forbidden}]")
print("complete_receipt_source_guard passed=1")
PY
  [ "$mode" = self-test ] || return 0
}

complete_receipt_write_signal_readiness() {
  local requested_signal="$1" control_root="$2" scratch="$3" artifact_dir="$4"
  local accepted_tree="$5" token="$6" readiness="$control_root/readiness.json"
  local release="$control_root/release.json"
  python3 -I - "$requested_signal" "$control_root" "$scratch" "$artifact_dir" \
    "$accepted_tree" "$token" "$readiness" "$release" "$$" <<'PY'
import json, os, pathlib, secrets, stat, sys

signal, root_raw, scratch_raw, artifact_raw, tree, token, readiness_raw, release_raw, pid_raw = sys.argv[1:]
root = pathlib.Path(root_raw).resolve(strict=True)
scratch = pathlib.Path(scratch_raw).resolve(strict=True)
artifact = pathlib.Path(artifact_raw).resolve(strict=True)
readiness = pathlib.Path(readiness_raw)
release = pathlib.Path(release_raw)

def directory_identity(path, expected_parent, reason):
    info = path.lstat()
    if path.is_symlink() or not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o700:
        raise SystemExit(f"complete_receipt_signal[{reason}]")
    if path.resolve(strict=True) != path or path.parent.resolve(strict=True) != expected_parent:
        raise SystemExit(f"complete_receipt_signal[{reason}]")
    return {"device": info.st_dev, "inode": info.st_ino, "mode": 0o700, "path": str(path), "type": "directory"}

if not root.is_absolute() or readiness.parent != root or release.parent != root:
    raise SystemExit("complete_receipt_signal[control-root-snapshot]")
if readiness.exists() or readiness.is_symlink() or release.exists() or release.is_symlink():
    raise SystemExit("complete_receipt_signal[coordination-fresh]")
root_identity = directory_identity(root, root.parent.resolve(strict=True), "control-root-snapshot")
scratch_identity = directory_identity(scratch, root, "scratch-snapshot")
artifact_identity = directory_identity(artifact, scratch, "artifact-snapshot")
record = {
    "artifact": artifact_identity,
    "case": f"complete_receipt_real_signal:{signal}",
    "child_pid": int(pid_raw),
    "control_root": root_identity,
    "invocation_token": token,
    "record_type": "readiness",
    "release_nonce": secrets.token_hex(32),
    "requested_signal": signal,
    "schema_version": 1,
    "scratch": scratch_identity,
    "tree": tree,
}
raw = json.dumps(record, sort_keys=True, separators=(",", ":"), allow_nan=False).encode() + b"\n"
flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
if hasattr(os, "O_NOFOLLOW"):
    flags |= os.O_NOFOLLOW
fd = os.open(readiness, flags, 0o600)
with os.fdopen(fd, "wb", closefd=True) as handle:
    handle.write(raw)
    handle.flush()
    os.fsync(handle.fileno())
parent_fd = os.open(root, os.O_RDONLY)
try:
    os.fsync(parent_fd)
finally:
    os.close(parent_fd)
info = readiness.lstat()
if not stat.S_ISREG(info.st_mode) or readiness.is_symlink() or stat.S_IMODE(info.st_mode) != 0o600:
    raise SystemExit("complete_receipt_signal[readiness-mode]")
if readiness.read_bytes() != raw:
    raise SystemExit("complete_receipt_signal[readiness-reopen]")
PY
}

complete_receipt_validate_signal_release() {
  local control_root="$1" scratch="$2" artifact_dir="$3"
  local readiness="$control_root/readiness.json" release="$control_root/release.json"
  python3 -I - "$control_root" "$scratch" "$artifact_dir" "$readiness" "$release" "$$" <<'PY'
import json, pathlib, stat, sys

root, scratch, artifact, readiness, release = map(pathlib.Path, sys.argv[1:6])
pid = int(sys.argv[6])

def reject(value):
    raise ValueError(value)

def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()

def decode(path, reason):
    info = path.lstat()
    if path.is_symlink() or not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600:
        raise SystemExit(f"complete_receipt_signal[{reason}]")
    raw = path.read_bytes()
    if raw.count(b"\n") != 1 or not raw.endswith(b"\n"):
        raise SystemExit(f"complete_receipt_signal[{reason}]")
    value = json.loads(raw[:-1], parse_constant=reject)
    if canonical(value) != raw[:-1]:
        raise SystemExit(f"complete_receipt_signal[{reason}]")
    return value, info

def validate_directory(path, promised, reason):
    info = path.lstat()
    if path.is_symlink() or not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o700:
        raise SystemExit(f"complete_receipt_signal[{reason}]")
    if promised != {"device": info.st_dev, "inode": info.st_ino, "mode": 0o700, "path": str(path), "type": "directory"}:
        raise SystemExit(f"complete_receipt_signal[{reason}]")

ready, ready_info = decode(readiness, "readiness-identity")
released, release_info = decode(release, "release-identity")
if ready_info.st_dev == release_info.st_dev and ready_info.st_ino == release_info.st_ino:
    raise SystemExit("complete_receipt_signal[release-identity]")
expected = dict(ready)
expected["record_type"] = "release"
if released != expected or released.get("child_pid") != pid:
    raise SystemExit("complete_receipt_signal[release-identity]")
validate_directory(root, ready.get("control_root"), "control-root-snapshot")
validate_directory(scratch, ready.get("scratch"), "scratch-snapshot")
validate_directory(artifact, ready.get("artifact"), "artifact-snapshot")
PY
}

complete_receipt_wait_for_signal_release() {
  local requested_signal="$1" control_root="$2" scratch="$3" artifact_dir="$4"
  local release="$control_root/release.json"
  if [ "$requested_signal" = EXIT ]; then
    while [ ! -e "$release" ]; do :; done
    complete_receipt_validate_signal_release "$control_root" "$scratch" "$artifact_dir"
    exit 0
  fi
  while :; do :; done
}

complete_receipt_real_signal_controls() {
  local scratch="$1" accepted_tree="$2"
  python3 -I - "$ROOT_DIR" "$scratch" "$accepted_tree" <<'PY'
import hashlib, json, os, pathlib, shutil, signal, stat, subprocess, sys, time

root = pathlib.Path(sys.argv[1]).resolve(strict=True)
scratch = pathlib.Path(sys.argv[2]).resolve(strict=True)
tree = sys.argv[3]
checker = root / "tools/check-phase285-witness-conformance.sh"
control_parent = scratch / "real-signal"
control_parent.mkdir(mode=0o700)

class RelationError(Exception):
    pass

def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()

def directory_record(path):
    info = path.lstat()
    return {"device": info.st_dev, "inode": info.st_ino, "mode": stat.S_IMODE(info.st_mode), "path": str(path), "type": "directory" if stat.S_ISDIR(info.st_mode) else "other"}

def wait_for_readiness(process, path):
    deadline = time.monotonic() + 2.0
    while time.monotonic() < deadline:
        if path.exists():
            return
        if process.poll() is not None:
            raise RelationError("readiness-process-exit")
        time.sleep(0.01)
    raise RelationError("readiness-timeout")

def decode_canonical_file(path, reason):
    info = path.lstat()
    raw = path.read_bytes()
    if path.is_symlink() or not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600:
        raise RelationError(reason)
    if raw.count(b"\n") != 1 or not raw.endswith(b"\n"):
        raise RelationError(reason)
    value = json.loads(raw[:-1])
    if canonical(value) != raw[:-1]:
        raise RelationError(reason)
    return value, info, raw

def revalidate_readiness(record, process, requested, case_root, root_before):
    expected_keys = {"artifact","case","child_pid","control_root","invocation_token","record_type","release_nonce","requested_signal","schema_version","scratch","tree"}
    if set(record) != expected_keys or record["schema_version"] != 1 or record["record_type"] != "readiness":
        raise RelationError("create-new-identity")
    if record["child_pid"] != process.pid or record["tree"] != tree or record["requested_signal"] != requested or record["case"] != f"complete_receipt_real_signal:{requested}":
        raise RelationError("create-new-identity")
    for name in ("invocation_token", "release_nonce"):
        value = record[name]
        if not isinstance(value, str) or len(value) != 64 or any(ch not in "0123456789abcdef" for ch in value):
            raise RelationError("create-new-identity")
    if directory_record(case_root) != record["control_root"] or (case_root.stat().st_dev, case_root.stat().st_ino) != root_before:
        raise RelationError("control-root-snapshot")
    scratch_path = pathlib.Path(record["scratch"].get("path", ""))
    artifact_path = pathlib.Path(record["artifact"].get("path", ""))
    if scratch_path.parent != case_root or artifact_path.parent != scratch_path:
        raise RelationError("create-new-identity")
    try:
        if directory_record(scratch_path) != record["scratch"]:
            raise RelationError("scratch-snapshot")
    except FileNotFoundError as error:
        raise RelationError("exit-before-release") from error
    try:
        if directory_record(artifact_path) != record["artifact"]:
            raise RelationError("artifact-snapshot")
    except FileNotFoundError as error:
        raise RelationError("artifact-snapshot") from error
    if record["control_root"]["mode"] != 0o700 or record["scratch"]["mode"] != 0o700 or record["artifact"]["mode"] != 0o700:
        raise RelationError("create-new-identity")
    return scratch_path, artifact_path

def write_release(case_root, readiness, mutate_case=False):
    release = case_root / "release.json"
    if release.exists() or release.is_symlink():
        raise RelationError("release-identity")
    value = dict(readiness)
    value["record_type"] = "release"
    if mutate_case:
        value["case"] = value["case"] + ":stale"
    raw = canonical(value) + b"\n"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(release, flags, 0o600)
    with os.fdopen(fd, "wb", closefd=True) as handle:
        handle.write(raw)
        handle.flush()
        os.fsync(handle.fileno())
    reopened, info, reopened_raw = decode_canonical_file(release, "release-identity")
    if reopened != value or reopened_raw != raw:
        raise RelationError("release-identity")
    parent_fd = os.open(case_root, os.O_RDONLY)
    try:
        os.fsync(parent_fd)
    finally:
        os.close(parent_fd)
    return info

def wait_status(process, timeout=2.0):
    try:
        return process.wait(timeout=timeout)
    except subprocess.TimeoutExpired as error:
        raise RelationError("signal-specific-termination") from error

def signal_and_validate(process, requested, scratch_path):
    process.send_signal(getattr(signal, f"SIG{requested}"))
    status = wait_status(process)
    if status != -getattr(signal, f"SIG{requested}"):
        raise RelationError("signal-specific-termination")
    if scratch_path.exists():
        raise RelationError("residue")

def launch(case_checker, requested, label):
    case_root = control_parent / label
    case_root.mkdir(mode=0o700)
    root_before = (case_root.stat().st_dev, case_root.stat().st_ino)
    readiness_path, release_path = case_root / "readiness.json", case_root / "release.json"
    if readiness_path.exists() or release_path.exists():
        raise RelationError("coordination-fresh")
    environment = os.environ.copy()
    environment["PHASE285_SERVICE_CHECKPOINT_TREE"] = tree
    process = subprocess.Popen(
        ["bash", str(case_checker), "--self-test", "complete-receipt-real-signal", requested, str(case_root)],
        cwd=case_checker.parent.parent,
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    scratch_path = None
    try:
        wait_for_readiness(process, readiness_path)
        readiness, _, _ = decode_canonical_file(readiness_path, "create-new-identity")
        promised_scratch = readiness.get("scratch", {}).get("path")
        if isinstance(promised_scratch, str) and promised_scratch:
            scratch_path = pathlib.Path(promised_scratch)
        scratch_path, artifact_path = revalidate_readiness(readiness, process, requested, case_root, root_before)
        return process, case_root, readiness, scratch_path, artifact_path
    except Exception:
        if process.poll() is None:
            process.send_signal(signal.SIGTERM)
            try:
                process.wait(timeout=2.0)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=2.0)
        if scratch_path is not None and scratch_path.exists():
            shutil.rmtree(scratch_path)
        raise

def finish_failure(process, scratch_path):
    if process.poll() is None:
        signal_and_validate(process, "TERM", scratch_path)
    elif scratch_path.exists():
        shutil.rmtree(scratch_path)

def run_action(case_checker, requested, label, action):
    process = None
    scratch_path = None
    try:
        process, case_root, readiness, scratch_path, artifact_path = launch(case_checker, requested, label)
        if action == "baseline":
            if requested == "EXIT":
                write_release(case_root, readiness)
                if wait_status(process) != 0:
                    raise RelationError("exit-status")
                if scratch_path.exists():
                    raise RelationError("residue")
            else:
                signal_and_validate(process, requested, scratch_path)
            return None
        if action == "omission":
            deadline = time.monotonic() + 0.25
            while time.monotonic() < deadline:
                if process.poll() is not None:
                    raise RelationError("exit-before-release")
                if directory_record(scratch_path) != readiness["scratch"]:
                    raise RelationError("residue")
                time.sleep(0.01)
            signal_and_validate(process, "TERM", scratch_path)
            return "release-timeout"
        if action == "stale_release":
            write_release(case_root, readiness, mutate_case=True)
            status = wait_status(process)
            output = process.stdout.read() if process.stdout is not None else ""
            if status == 0 or "complete_receipt_signal[release-identity]" not in output or scratch_path.exists():
                raise RelationError("release-identity")
            return "release-identity"
        if action == "root_mode":
            case_root.chmod(0o755)
            try:
                revalidate_readiness(readiness, process, requested, case_root, (readiness["control_root"]["device"], readiness["control_root"]["inode"]))
                raise RelationError("root-mode-survived")
            except RelationError as error:
                if str(error) != "control-root-snapshot":
                    raise
            finally:
                case_root.chmod(0o700)
            signal_and_validate(process, "TERM", scratch_path)
            return "control-root-snapshot"
        if action == "artifact_mode":
            artifact_path.chmod(0o755)
            try:
                revalidate_readiness(readiness, process, requested, case_root, (readiness["control_root"]["device"], readiness["control_root"]["inode"]))
                raise RelationError("artifact-mode-survived")
            except RelationError as error:
                if str(error) != "artifact-snapshot":
                    raise
            finally:
                artifact_path.chmod(0o700)
            signal_and_validate(process, "TERM", scratch_path)
            return "artifact-snapshot"
        if action == "early_exit":
            status = wait_status(process, 1.0)
            if status != 0 or scratch_path.exists():
                raise RelationError("exit-before-release")
            return "exit-before-release"
        if action == "signal":
            try:
                signal_and_validate(process, requested, scratch_path)
            except RelationError as error:
                return str(error)
            return None
        raise RelationError("unknown-action")
    except RelationError as error:
        if process is not None and scratch_path is not None and process.poll() is None:
            finish_failure(process, scratch_path)
        return str(error)
    finally:
        if process is not None and process.poll() is None:
            process.kill()
            process.wait(timeout=2.0)
        if scratch_path is not None and scratch_path.exists():
            shutil.rmtree(scratch_path)

for requested in ("EXIT", "HUP", "INT", "TERM"):
    reason = run_action(checker, requested, f"baseline-{requested.lower()}", "baseline")
    if reason is not None:
        raise SystemExit(f"complete_receipt_real_signal[{requested}:{reason}]")
    print(f"complete_receipt_real_signal signal={requested} release={'1' if requested == 'EXIT' else '0'} cleaned=1 passed=1")

source = checker.read_text()
control_start = source.index("complete_receipt_real_signal_controls() {")
control_end = source.index("\n}\n\nrun_complete_receipt_focus()", control_start) + 3
control_block = source[control_start:control_end]
control_marker = "__PHASE285_COMPLETE_RECEIPT_SIGNAL_CONTROL_BLOCK__"
mutation_template = source[:control_start] + control_marker + source[control_end:]

def source_mutant(label, old, new):
    if mutation_template.count(old) != 1:
        raise SystemExit(f"complete_receipt_real_signal_mutant[{label}:anchor:{mutation_template.count(old)}]")
    mutant = mutation_template.replace(old, new, 1).replace(control_marker, control_block, 1)
    digest = hashlib.sha256(mutant.encode()).hexdigest()
    mutant_root = control_parent / f"mutant-root-{label}"
    (mutant_root / "tools").mkdir(parents=True, mode=0o700)
    for relative in ("crates/swarm-governance-witness/src/lib.rs", "crates/swarm-governance-witness/tests/service_checkpoint.rs"):
        destination = mutant_root / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(root / relative, destination)
    subprocess.run(["git", "init", "-q"], cwd=mutant_root, check=True)
    mutant_checker = mutant_root / "tools/check-phase285-witness-conformance.sh"
    mutant_checker.write_text(mutant)
    mutant_checker.chmod(0o700)
    return mutant_checker, digest

inherited = [
    ("checkpoint_before_trap", "TERM", "  complete_receipt_arm_cleanup_traps\n  artifact_dir=\"$scratch/artifacts\"", "  artifact_dir=\"$scratch/artifacts\"", "residue"),
    ("fabricated_readiness", "TERM", '"child_pid": int(pid_raw),', '"child_pid": int(pid_raw) + 1,', "create-new-identity"),
    ("ignored_signal", "HUP", "  trap 'complete_receipt_cleanup_on_signal HUP' HUP", "  trap '' HUP", "signal-specific-termination"),
    ("normal_exit", "TERM", "  trap 'complete_receipt_cleanup_on_signal TERM' TERM", "  trap 'exit 0' TERM", "signal-specific-termination"),
    ("trap_removal", "TERM", "  complete_receipt_arm_cleanup_traps", "  : # cleanup trap arm removed", "residue"),
    ("trap_substitution", "HUP", "  trap 'complete_receipt_cleanup_on_signal HUP' HUP", "  trap 'complete_receipt_cleanup_on_signal TERM' HUP", "signal-specific-termination"),
]
digests = set()
for label, requested, old, new, expected in inherited:
    mutant_checker, digest = source_mutant(label, old, new)
    if label == "checkpoint_before_trap":
        mutant_text = mutant_checker.read_text()
        wait_call = '    complete_receipt_wait_for_signal_release "$requested_signal" "$control_root" "$scratch" "$artifact_dir"'
        focus_start = mutant_text.index("\nrun_complete_receipt_focus() {\n") + 1
        focus_end = mutant_text.index("\n}\n\nrun_complete_receipt_mutants()", focus_start) + 3
        focus = mutant_text[focus_start:focus_end]
        if focus.count(wait_call) != 1:
            raise SystemExit("complete_receipt_real_signal_mutant[checkpoint-before-trap-call]")
        focus = focus.replace(wait_call, '    while [ ! -e "$control_root/release.json" ]; do :; done\n    complete_receipt_arm_cleanup_traps\n' + wait_call, 1)
        mutant_checker.write_text(mutant_text[:focus_start] + focus + mutant_text[focus_end:])
        digest = hashlib.sha256(mutant_checker.read_bytes()).hexdigest()
    if digest in digests:
        raise SystemExit("complete_receipt_real_signal_mutant[duplicate]")
    digests.add(digest)
    observed = run_action(mutant_checker, requested, f"mutant-{label}", "signal")
    if observed != expected:
        raise SystemExit(f"complete_receipt_real_signal_mutant[{label}:expected={expected}:observed={observed}]")
    print(f"complete_receipt_real_signal_mutation mutation={label} intended={expected} source_sha256={digest} executed=1 killed=1 vacuous=0")

release_controls = [
    ("release_omission", checker, "EXIT", "omission", "release-timeout"),
    ("stale_cross_case_release", checker, "EXIT", "stale_release", "release-identity"),
    ("control_root_mode_widening", checker, "EXIT", "root_mode", "control-root-snapshot"),
    ("artifact_mode_widening", checker, "EXIT", "artifact_mode", "artifact-snapshot"),
]
early_checker, early_digest = source_mutant(
    "early_exit",
    '    complete_receipt_wait_for_signal_release "$requested_signal" "$control_root" "$scratch" "$artifact_dir"',
    "    exit 0",
)
fixed_checker, fixed_digest = source_mutant(
    "fixed_sleep",
    '    while [ ! -e "$release" ]; do :; done',
    "    sleep 0.25\n    exit 0",
)
release_controls.extend([
    ("early_exit", early_checker, "EXIT", "early_exit", "exit-before-release"),
    ("fixed_sleep_substitution", fixed_checker, "EXIT", "early_exit", "exit-before-release"),
])
for label, case_checker, requested, action, expected in release_controls:
    observed = run_action(case_checker, requested, f"release-{label}", action)
    if observed != expected:
        raise SystemExit(f"complete_receipt_release_mutant[{label}:expected={expected}:observed={observed}]")
    print(f"complete_receipt_release_mutation mutation={label} intended={expected} executed=1 killed=1 vacuous=0")
print(f"complete_receipt_real_signal_self_test cases=4 inherited_mutations=6 release_metadata=6 lifecycle=25 unique_source_mutations={len(digests)+2} passed=1")
PY
}

run_complete_receipt_focus() {
  local requested_signal="${1:-}" control_root="${2:-}"
  local accepted_tree="${PHASE285_SERVICE_CHECKPOINT_TREE:?PHASE285_SERVICE_CHECKPOINT_TREE required}"
  local scratch scratch_mode artifact_dir ledger receipt snapshot internal_output external_output internal_list_output external_list_output token
  [[ "$accepted_tree" =~ ^[0-9a-f]{40}$ ]] || { echo "complete receipt tree is malformed" >&2; return 1; }
  complete_receipt_source_guard normal
  if [ -n "$requested_signal" ]; then
    [[ "$control_root" = /* ]] || { echo "complete receipt signal control root must be absolute" >&2; return 2; }
    scratch_mode="$(phase285_directory_metadata "$control_root" 2>/dev/null)" || scratch_mode=""
    [ "${scratch_mode%%:*}" = 700 ] \
      && [ ! -e "$control_root/readiness.json" ] && [ ! -L "$control_root/readiness.json" ] \
      && [ ! -e "$control_root/release.json" ] && [ ! -L "$control_root/release.json" ] || {
      echo "complete receipt signal control root is invalid" >&2; return 2;
    }
    scratch="$(phase285_create_confined_scratch phase285-complete-receipt "$control_root")"
  else
    scratch="$(phase285_create_confined_scratch phase285-complete-receipt)"
  fi
  PHASE285_WITNESS_TEMP_DIR="$scratch"
  IFS=: read -r scratch_mode PHASE285_COMPLETE_RECEIPT_BOUND_DEVICE PHASE285_COMPLETE_RECEIPT_BOUND_INODE \
    < <(phase285_directory_metadata "$scratch")
  [ -n "$PHASE285_COMPLETE_RECEIPT_BOUND_DEVICE" ] && [ -n "$PHASE285_COMPLETE_RECEIPT_BOUND_INODE" ] || {
    echo "complete receipt scratch identity is absent" >&2; return 1;
  }
  complete_receipt_arm_cleanup_traps
  artifact_dir="$scratch/artifacts"
  mkdir -m 700 "$artifact_dir"
  ledger="$artifact_dir/ledger.json"
  receipt="$artifact_dir/receipt.json"
  snapshot="$artifact_dir/snapshot.json"
  internal_output="$scratch/internal.txt"
  external_output="$scratch/external.txt"
  internal_list_output="$scratch/internal-list.txt"
  external_list_output="$scratch/external-list.txt"
  token="$(python3 -I - "$accepted_tree" <<'PY'
import hashlib, os, secrets, sys
print(hashlib.sha256((sys.argv[1]+":"+str(os.getpid())+":"+secrets.token_hex(32)).encode()).hexdigest())
PY
)"
  if [ -n "$requested_signal" ]; then
    complete_receipt_write_signal_readiness "$requested_signal" "$control_root" "$scratch" \
      "$artifact_dir" "$accepted_tree" "$token"
    complete_receipt_wait_for_signal_release "$requested_signal" "$control_root" "$scratch" "$artifact_dir"
  fi
  umask 077
  [ ! -e "$ledger" ] && [ ! -e "$receipt" ] || return 1
  cargo test -p swarm-governance-witness --lib --locked --offline -- --list >"$internal_list_output"
  PHASE285_COMPLETE_RECEIPT_LEDGER_PATH="$ledger" PHASE285_COMPLETE_RECEIPT_PATH="$receipt" \
  PHASE285_COMPLETE_RECEIPT_INVOCATION_TOKEN="$token" \
    cargo test -p swarm-governance-witness --lib --locked --offline -- --test-threads=1 --ignored \
      service_checkpoint_relay_tests::complete_receipt_authority_and_grants_are_observed --exact | tee "$internal_output"
  python3 -I - "$internal_output" "$internal_list_output" \
    service_checkpoint_relay_tests::complete_receipt_authority_and_grants_are_observed <<'PY'
import re, sys
text=open(sys.argv[1],encoding="utf-8").read(); inventory=[]
for line in open(sys.argv[2],encoding="utf-8"):
    match=re.fullmatch(r"([^:]+(?:::[^:]+)*): test\n?",line)
    if match: inventory.append(match.group(1))
if len(inventory)!=len(set(inventory)) or inventory.count(sys.argv[3])!=1: raise SystemExit("complete receipt internal inventory differs")
expected=("1","0","0",str(len(inventory)-1))
if re.findall(r"^running (\d+) test",text,re.M)!=["1"] or re.findall(r"^test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored; \d+ measured; (\d+) filtered out;",text,re.M)!=[expected]: raise SystemExit("complete receipt internal transcript differs")
PY
  ci_harness_record_passed lib \
    service_checkpoint_relay_tests::complete_receipt_authority_and_grants_are_observed "$internal_output"
  complete_receipt_artifact_snapshot "$artifact_dir" "$ledger" "$receipt" "$snapshot" record
  cargo test -p swarm-governance-witness --test service_checkpoint --locked --offline -- --list >"$external_list_output"
  PHASE285_COMPLETE_RECEIPT_LEDGER_PATH="$ledger" PHASE285_COMPLETE_RECEIPT_PATH="$receipt" \
  PHASE285_COMPLETE_RECEIPT_INVOCATION_TOKEN="$token" \
    cargo test -p swarm-governance-witness --test service_checkpoint --locked --offline -- --test-threads=1 --ignored \
      complete_receipt_validation_precedes_suppression_and_failures_forward --exact | tee "$external_output"
  python3 -I - "$external_output" "$external_list_output" \
    complete_receipt_validation_precedes_suppression_and_failures_forward <<'PY'
import re, sys
text=open(sys.argv[1],encoding="utf-8").read(); inventory=[]
for line in open(sys.argv[2],encoding="utf-8"):
    match=re.fullmatch(r"([^:]+(?:::[^:]+)*): test\n?",line)
    if match: inventory.append(match.group(1))
if len(inventory)!=len(set(inventory)) or inventory.count(sys.argv[3])!=1: raise SystemExit("complete receipt external inventory differs")
expected=("1","0","0",str(len(inventory)-1))
if re.findall(r"^running (\d+) test",text,re.M)!=["1"] or re.findall(r"^test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored; \d+ measured; (\d+) filtered out;",text,re.M)!=[expected]: raise SystemExit("complete receipt external transcript differs")
PY
  ci_harness_record_passed service_checkpoint \
    complete_receipt_validation_precedes_suppression_and_failures_forward "$external_output"
  complete_receipt_artifact_snapshot "$artifact_dir" "$ledger" "$receipt" "$snapshot" verify
  complete_receipt_artifact_hostile_controls "$scratch" "$ledger" "$receipt"
  complete_receipt_real_signal_controls "$scratch" "$accepted_tree"
  run_complete_receipt_mutants "$accepted_tree" "$scratch"
  echo "complete_receipt_execution internal=1 external=1 mutants=10 lifecycle=25 vacuous=0 passed=1"
  cleanup_temp_dir
  trap - EXIT HUP INT TERM
}

run_complete_receipt_mutants() {
  local accepted_tree="$1" parent_scratch="$2"
  python3 -I - "$ROOT_DIR" "$parent_scratch" "$accepted_tree" <<'PY'
import hashlib, json, os, pathlib, shutil, subprocess, sys, time, urllib.error, urllib.request
root=pathlib.Path(sys.argv[1]).resolve(); parent=pathlib.Path(sys.argv[2]).resolve(); tree=sys.argv[3]
exact=parent/"exact-tree"; exact.mkdir()
archive=subprocess.Popen(["git","-C",str(root),"archive",tree],stdout=subprocess.PIPE)
unpack=subprocess.run(["tar","-xf","-","-C",str(exact)],stdin=archive.stdout,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,check=False)
archive.stdout.close()
if archive.wait()!=0 or unpack.returncode!=0: raise SystemExit("complete_receipt_mutant[extract]")
owned=["crates/swarm-governance-witness/src/lib.rs","crates/swarm-governance-witness/tests/service_checkpoint.rs","tools/check-phase285-witness-conformance.sh","tools/fixtures/phase285-witness-integrity.json"]
for relative in owned:
    destination=exact/relative; destination.parent.mkdir(parents=True,exist_ok=True); shutil.copy2(root/relative,destination)
library=exact/"crates/swarm-governance-witness/src/lib.rs"; original=library.read_text()
def replace_once(text,old,new,label):
    if text.count(old)!=1: raise SystemExit(f"complete_receipt_mutant[{label}:anchor:{text.count(old)}]")
    return text.replace(old,new,1)
insert_anchor='''        let worker_bytes = must(
            canonical_wire_bytes(&worker_events),
            "observation worker bytes",
        );'''
response_received_anchor='''        let response_received_at_nanos = observation_clock.now();'''
response_binding='''        let response = if let Some(relay) = relay_legs.as_mut() {'''
worker_binding='''        let worker_events = observer
            .events
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .filter(|event| {
                !matches!(
                    event,
                    WorkerTransitionEventV1::ReceiptDeadlineIdentity { .. }
                )
            })
            .cloned()
            .collect::<Vec<_>>();'''
store_binding='''        let store_operations = facts
            .records
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();'''
publisher_binding='''        let publisher = CompletePublisherObservationV1 {'''
connections_binding='''        let connections = vec!['''
mutations=[]
# Mutants alter the accepted producer, rederive ledger/receipt digests, and bypass only the matching private relation so the external decoder is the stable kill point.
text=replace_once(original,response_binding,response_binding.replace("let response =","let mut response ="),"public_store_head")
injected='''        response.response = WitnessReadResponseV1::Head(Box::new(None));
        response.signature = evidence_signer.sign(&must(response.signing_bytes(), "mutated public head signing bytes"));
'''+response_received_anchor
text=replace_once(text,response_received_anchor,injected,"public_store_head")
producer_public_head='''        let public_head = match &response.response {
            WitnessReadResponseV1::Head(head) => must_some(
                head.as_ref().as_ref(),
                "observation public ReadHead is absent",
            ),
            _ => panic!("observation public response is not ReadHead"),
        };
        assert_eq!(
            public_head, selected_head,
            "observation public head differs from authenticated store head"
        );'''
text=replace_once(text,producer_public_head,"        let _ = (&response, selected_head);","public_store_head")
relay_response_binding='''            assert_eq!(
                held.response_bytes, response_bytes,
                "live relay response bytes"
            );'''
text=replace_once(text,relay_response_binding,"            let _ = (&held.response_bytes, &response_bytes);","public_store_head")
relay_replay_binding='''            assert_eq!(replay, response, "live relay replay response differs");'''
text=replace_once(text,relay_replay_binding,"            let _ = (&replay, &response);","public_store_head")
old='''        if head.as_ref().as_ref() != Some(selected_head)
            || read.target_txid != selected_head.txid
            || ledger_string(&row, "selected_head_txid", "public_store_head")? != selected_head.txid
        {
            return Err("public_store_head");
        }'''
text=replace_once(text,old,"        let _ = (head, &read, selected_head);","public_store_head")
mutations.append(("public_store_head",text,"public/store Head"))
for label,replacement,reason in [
 ("worker_operation",'''        worker_events[2] = WorkerTransitionEventV1::ProxyStoreBegin { worker: WorkerKindV1::Public, operation: "inspect_ready", cas_attempted: false };\n''',"worker operation"),
 ("worker_cas",'''        worker_events[2] = WorkerTransitionEventV1::ProxyStoreBegin { worker: WorkerKindV1::Public, operation: "read_entry", cas_attempted: true };\n''',"worker CAS"),
]:
    text=replace_once(original,worker_binding,worker_binding.replace("let worker_events =","let mut worker_events ="),label)
    text=replace_once(text,insert_anchor,replacement+insert_anchor,label)
    text=replace_once(text,"        validate_complete_worker_events(events)?;","        let _ = events;",label)
    mutations.append((label,text,reason))
for label,field_name,reason in [("store_input_digest","input_sha256","store input digest"),("store_result_digest","result_sha256","store result digest")]:
    text=replace_once(original,store_binding,store_binding.replace("let store_operations =","let mut store_operations ="),label)
    text=replace_once(text,insert_anchor,f'''        store_operations[0].{field_name} = "0".repeat(64);\n'''+insert_anchor,label)
    if label=="store_input_digest":
        old='''        let store_input = ledger_digest_matches(
            &store[0],
            "input_canonical_hex",
            "input_sha256",
            "store_input_digest",
        )?;'''; new='''        let store_input = ledger_hex(&store[0], "input_canonical_hex", "store_input_digest")?;'''
    else:
        old='''        let store_result_bytes = ledger_digest_matches(
            &store[0],
            "result_canonical_hex",
            "result_sha256",
            "store_result_digest",
        )?;'''; new='''        let store_result_bytes = ledger_hex(&store[0], "result_canonical_hex", "store_result_digest")?;'''
    text=replace_once(text,old,new,label); mutations.append((label,text,reason))
text=replace_once(original,publisher_binding,publisher_binding.replace("let publisher =","let mut publisher ="),"publisher_reply_subject")
text=replace_once(text,insert_anchor,'        publisher.reply_subject = "_R_.phase285-mutant".to_string();\n'+insert_anchor,"publisher_reply_subject")
old='''        if ledger_string(admission, "reply_subject", "publisher_reply_subject")? != reply
            || ledger_string(admission, "subject", "publisher_reply_subject")?
                != "swarm.governance.witness.v1.read_head"
            || ledger_string(admission, "payload_sha256", "publisher_reply_subject")?
                != sha256_hex(&request_bytes)
            || ledger_u64(admission, "deadline_millis", "publisher_reply_subject")?
                != PUBLIC_HANDLER_DEADLINE_MILLIS
        {
            return Err("publisher_reply_subject");
        }'''
text=replace_once(text,old,"        let _ = admission;","publisher_reply_subject"); mutations.append(("publisher_reply_subject",text,"publisher reply subject"))
text=replace_once(original,connections_binding,connections_binding.replace("let connections =","let mut connections ="),"connection_identity")
text=replace_once(text,insert_anchor,"        connections[0].server_client_id += 1;\n"+insert_anchor,"connection_identity")
text=replace_once(text,"        validate_complete_connections(connections)?;","        let _ = connections;","connection_identity")
old='''        if connection_client_ids.len() != connections.len()
            || connection_client_ids
                .iter()
                .zip(connections)
                .any(|(client_id, connection)| {
                    client_id.as_u64()
                        != connection
                            .get("server_client_id")
                            .and_then(serde_json::Value::as_u64)
                })
        {
            return Err("connection_identity");
        }'''
text=replace_once(text,old,"        let _ = connection_client_ids;","connection_identity"); mutations.append(("connection_identity",text,"connection identity"))

proxy_binding='''        let proxy_exchanges = proxy_records
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();'''
text=replace_once(original,proxy_binding,proxy_binding.replace("let proxy_exchanges =","let mut proxy_exchanges ="),"proxy_cross_copy")
text=replace_once(text,insert_anchor,'        proxy_exchanges[0] = private_exchanges[0].clone();\n'+insert_anchor,"proxy_cross_copy")
old='''        if proxy.len() != 1
            || canonical_value_bytes(&proxy[0], "proxy_cross_copy")?
                != canonical_value_bytes(&private[2], "proxy_cross_copy")?
        {
            return Err("proxy_cross_copy");
        }'''
new='''        if proxy.len() != 1
            || (canonical_value_bytes(&proxy[0], "proxy_cross_copy")?
                != canonical_value_bytes(&private[2], "proxy_cross_copy")?
                && canonical_value_bytes(&proxy[0], "proxy_cross_copy")?
                    != canonical_value_bytes(&private[0], "proxy_cross_copy")?)
        {
            return Err("proxy_cross_copy");
        }'''
text=replace_once(text,old,new,"proxy_cross_copy")
mutations.append(("proxy_cross_copy",text,"proxy cross-copy"))

publisher_collection='''        let response_enqueue_attempts: Vec<_> = worker_events'''
text=replace_once(original,publisher_collection,publisher_collection.replace("let response_enqueue_attempts", "let mut response_enqueue_attempts"),"response_enqueue_fabrication")
text=replace_once(text,insert_anchor,'        response_enqueue_attempts[0].ordinal = 11;\n        response_enqueue_attempts[0].worker = WorkerKindV1::Public;\n'+insert_anchor,"response_enqueue_fabrication")
text=replace_once(text,'        let expected = [(8_u64, "private"), (11_u64, "public")];','        let expected = [(11_u64, "public"), (11_u64, "public")];',"response_enqueue_fabrication")
mutations.append(("response_enqueue_fabrication",text,"response enqueue fabrication"))

identity_guard='''        if ledger_string(&row, "tree", "current_invocation")? != expected_tree
            || ledger_string(&row, "invocation_token", "current_invocation")?
                != expected_invocation_token
            || ledger_string(&row, "case", "current_invocation")? != expected_case
        {
            return Err("current_invocation");
        }'''
identity_bypass='''        let _ = (expected_tree, expected_invocation_token, expected_case);'''
current_invocation_mutant=replace_once(original,identity_guard,identity_bypass,"current_invocation")
if len(mutations)!=9: raise SystemExit("complete_receipt_mutant[inventory-external]")
digests=set(); target=parent/"compiled-target"; base=os.environ.copy(); base["CARGO_TARGET_DIR"]=str(target); base["CARGO_NET_OFFLINE"]="true"
for variable in list(base):
    if variable.startswith("PHASE285_TOPOLOGY_"): del base[variable]
nats_http_url=base.get("NATS_HTTP_URL")
if not nats_http_url: raise SystemExit("complete_receipt_mutant[nats-monitor-absent]")
monitor_port_path_raw=base.get("SWARM_NATS_CURRENT_HTTP_PORT_FILE")
if not monitor_port_path_raw: raise SystemExit("complete_receipt_mutant[nats-monitor-port-file-absent]")
monitor_port_path=pathlib.Path(monitor_port_path_raw)
if not monitor_port_path.is_absolute() or monitor_port_path.parent.resolve(strict=True)!=pathlib.Path(base["SWARM_NATS_HARNESS_SCRATCH"]).resolve(strict=True): raise SystemExit("complete_receipt_mutant[nats-monitor-port-file-boundary]")
def current_monitor_url():
    before=monitor_port_path.lstat()
    if monitor_port_path.is_symlink() or not monitor_port_path.is_file() or before.st_size>6: raise SystemExit("complete_receipt_mutant[nats-monitor-port-file-identity]")
    raw=monitor_port_path.read_bytes(); after=monitor_port_path.lstat()
    if (before.st_dev,before.st_ino,before.st_mode,before.st_size)!=(after.st_dev,after.st_ino,after.st_mode,after.st_size): raise SystemExit("complete_receipt_mutant[nats-monitor-port-file-changed]")
    if not raw.endswith(b"\n") or raw.count(b"\n")!=1 or not raw[:-1].isdigit(): raise SystemExit("complete_receipt_mutant[nats-monitor-port-file-framing]")
    port=int(raw[:-1])
    if not 1<=port<=65535: raise SystemExit("complete_receipt_mutant[nats-monitor-port-file-range]")
    return f"http://127.0.0.1:{port}"
def connection_count():
    deadline=time.monotonic()+10.0; last_error=None
    while time.monotonic()<deadline:
        try:
            with urllib.request.urlopen(current_monitor_url()+"/connz", timeout=1.0) as response:
                return int(json.load(response)["num_connections"])
        except (OSError, urllib.error.URLError, TimeoutError, json.JSONDecodeError, KeyError, TypeError, ValueError) as error:
            last_error=error; time.sleep(0.05)
    raise SystemExit("complete_receipt_mutant[nats-monitor-unavailable]") from last_error
baseline_connections=connection_count()
def await_connection_quiescence():
    deadline=time.monotonic()+10.0
    while time.monotonic()<deadline:
        if connection_count()<=baseline_connections: return
        time.sleep(0.02)
    raise SystemExit("complete_receipt_mutant[nats-connections-not-quiescent]")
for name,source,reason in mutations:
    digest=hashlib.sha256(source.encode()).hexdigest()
    if digest in digests: raise SystemExit("complete_receipt_mutant[duplicate]")
    # Cargo checks local source freshness by timestamp. Separate rewrites by a
    # full filesystem timestamp tick so one mutant cannot execute another's
    # cached binary.
    time.sleep(1.05); digests.add(digest); library.write_text(source)
    artifacts=parent/f"mutant-{name}"; artifacts.mkdir(); ledger=artifacts/"ledger.json"; receipt=artifacts/"receipt.json"
    env=base.copy(); env["PHASE285_COMPLETE_RECEIPT_LEDGER_PATH"]=str(ledger); env["PHASE285_COMPLETE_RECEIPT_PATH"]=str(receipt); env["PHASE285_SERVICE_CHECKPOINT_TREE"]=tree; env["PHASE285_COMPLETE_RECEIPT_INVOCATION_TOKEN"]=hashlib.sha256((tree+":"+name).encode()).hexdigest()
    internal=["cargo","test","-p","swarm-governance-witness","--lib","--locked","--offline","--","--test-threads=1","--ignored","service_checkpoint_relay_tests::complete_receipt_authority_and_grants_are_observed","--exact"]
    external=["cargo","test","-p","swarm-governance-witness","--test","service_checkpoint","--locked","--offline","--","--test-threads=1","--ignored","complete_receipt_validation_precedes_suppression_and_failures_forward","--exact"]
    await_connection_quiescence()
    try: first=subprocess.run(internal,cwd=exact,env=env,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=120)
    except subprocess.TimeoutExpired as error: raise SystemExit(f"complete_receipt_mutant[{name}:internal-timeout]") from error
    if first.returncode!=0 or "running 1 test" not in first.stdout or "1 passed; 0 failed" not in first.stdout: raise SystemExit(f"complete_receipt_mutant[{name}:internal-vacuous]\n{first.stdout}")
    try: second=subprocess.run(external,cwd=exact,env=env,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=120)
    except subprocess.TimeoutExpired as error: raise SystemExit(f"complete_receipt_mutant[{name}:external-timeout]") from error
    if second.returncode==0 or "running 1 test" not in second.stdout or "0 passed; 1 failed" not in second.stdout or reason not in second.stdout: raise SystemExit(f"complete_receipt_mutant[{name}:wrong-reason]\n{second.stdout}")
    await_connection_quiescence()
    print(f"complete_receipt_mutant name={name} internal=1 external=1 intended={reason} source_sha256={digest} compiled=1 killed=1 vacuous=0")
name="current_invocation"; source=current_invocation_mutant; digest=hashlib.sha256(source.encode()).hexdigest()
if digest in digests: raise SystemExit("complete_receipt_mutant[current_invocation:duplicate]")
time.sleep(1.05); digests.add(digest); library.write_text(source)
artifacts=parent/"mutant-current-invocation"; artifacts.mkdir(); ledger=artifacts/"ledger.json"; receipt=artifacts/"receipt.json"
env=base.copy(); env["PHASE285_COMPLETE_RECEIPT_LEDGER_PATH"]=str(ledger); env["PHASE285_COMPLETE_RECEIPT_PATH"]=str(receipt); env["PHASE285_SERVICE_CHECKPOINT_TREE"]=tree; env["PHASE285_COMPLETE_RECEIPT_INVOCATION_TOKEN"]=hashlib.sha256((tree+":"+name).encode()).hexdigest()
internal=["cargo","test","-p","swarm-governance-witness","--lib","--locked","--offline","--","--test-threads=1","--ignored","service_checkpoint_relay_tests::complete_receipt_authority_and_grants_are_observed","--exact"]
await_connection_quiescence()
try: result=subprocess.run(internal,cwd=exact,env=env,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=120)
except subprocess.TimeoutExpired as error: raise SystemExit("complete_receipt_mutant[current_invocation:timeout]") from error
if result.returncode==0 or "running 1 test" not in result.stdout or "0 passed; 1 failed" not in result.stdout or "cross invocation complete receipt suppressed" not in result.stdout: raise SystemExit(f"complete_receipt_mutant[current_invocation:wrong-reason]\n{result.stdout}")
print(f"complete_receipt_mutant name={name} internal=1 external=0 intended=current-invocation source_sha256={digest} compiled=1 killed=1 vacuous=0")
library.write_text(original)
if len(digests)!=10: raise SystemExit(f"complete_receipt_mutant[unique:{len(digests)}]")
print(f"complete_receipt_source_guard_self_test mutations=10 unique={len(digests)} compiled=10 executed_internal=10 executed_external=9 killed=10 vacuous=0 tree={tree} passed=1")
PY
}

topology_artifact_snapshot() {
  local mode="$1" snapshot="$2"
  shift 2
  python3 -I - "$mode" "$snapshot" "$@" <<'PY'
import hashlib,json,pathlib,stat,sys
mode=sys.argv[1]; snapshot=pathlib.Path(sys.argv[2]); specifications=sys.argv[3:]
prior={} if mode=="record" else json.loads(snapshot.read_text())
current=dict(prior)
projection_identities=[]
observed={}
for specification in specifications:
    raw,limit=specification.rsplit(":",1); path=pathlib.Path(raw); maximum=int(limit); metadata=path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode) or not 1<=metadata.st_size<=maximum: raise SystemExit("topology_snapshot[bound]")
    if stat.S_IMODE(metadata.st_mode)!=0o600: raise SystemExit("topology_snapshot[mode]")
    value=path.read_bytes(); after=path.lstat()
    row={"length":metadata.st_size,"sha256":hashlib.sha256(value).hexdigest(),"device":metadata.st_dev,"inode":metadata.st_ino,"mode":stat.S_IMODE(metadata.st_mode)}
    if (metadata.st_dev,metadata.st_ino,metadata.st_mode,metadata.st_size)!=(after.st_dev,after.st_ino,after.st_mode,after.st_size) or len(value)!=metadata.st_size: raise SystemExit("topology_snapshot[identity]")
    key=str(path.resolve())
    observed[key]=row
    current[key]=row
    if maximum==16384: projection_identities.append((metadata.st_dev,metadata.st_ino))
if len(projection_identities)!=len(set(projection_identities)): raise SystemExit("topology_snapshot[alias]")
for key,row in observed.items():
    if key in prior and prior[key]!=row: raise SystemExit("topology_snapshot[changed]")
framed=json.dumps(current,sort_keys=True,separators=(",",":")).encode()+b"\n"
if mode=="record":
    snapshot.write_bytes(framed)
elif mode=="extend":
    snapshot.write_bytes(framed)
elif snapshot.read_bytes()!=framed:
    raise SystemExit("topology_snapshot[reopen]")
PY
}

topology_owner_block_focus() {
  local tree="${PHASE285_SERVICE_CHECKPOINT_TREE:?}" token harness_root canonical probe
  local rust_canonical rust_probe shell_canonical shell_probe topology_root snapshot internal_output external_output
  local config_output comparator_output projection_output
  local credential_path
  local -a topology_credential_paths topology_snapshot_inputs
  harness_root="${PHASE285_CI_ROUTE_TEMP_PARENT:-${SWARM_NATS_HARNESS_SCRATCH:?}}"
  canonical="${PHASE285_TOPOLOGY_CONFIG_PATH:?}"
  token="$(openssl rand -hex 32)"
  [[ "$token" =~ ^[0-9a-f]{64}$ ]] || return 1
  topology_root="$harness_root/topology-$token"
  mkdir -m 700 -- "$topology_root"
  probe="$topology_root/probe.conf"
  rust_canonical="$topology_root/rust-canonical.json"
  rust_probe="$topology_root/rust-probe.json"
  shell_canonical="$topology_root/shell-canonical.json"
  shell_probe="$topology_root/shell-probe.json"
  snapshot="$topology_root/snapshot.json"
  internal_output="$topology_root/internal.txt"
  external_output="$topology_root/external.txt"
  config_output="$topology_root/config-controls.txt"
  comparator_output="$topology_root/comparator-controls.txt"
  projection_output="$topology_root/projection-controls.txt"

  topology_credential_paths=(
    "${PHASE285_TOPOLOGY_RUNTIME_CREDENTIAL_PATH:?}"
    "${PHASE285_TOPOLOGY_WITNESS_CREDENTIAL_PATH:?}"
  )
  if [ -n "${PHASE285_RELAY_TOPOLOGY_TOKEN:-}" ]; then
    topology_credential_paths+=("${SWARM_NATS_RELAY_CREDENTIAL_PATH:?}")
  fi
  topology_credential_paths+=(
    "${PHASE285_TOPOLOGY_STORE_CREDENTIAL_PATH:?}"
    "${PHASE285_TOPOLOGY_INIT_CREDENTIAL_PATH:?}"
  )
  for credential_path in "${topology_credential_paths[@]}"; do
    topology_snapshot_inputs+=("$credential_path:4096")
  done

  python3 -I - "$canonical" "$probe" "${topology_credential_paths[@]}" <<'PY'
import os, pathlib, re, secrets, stat, sys
config,probe,*credentials=map(pathlib.Path,sys.argv[1:])
def bounded(path,maximum):
    metadata=path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode) or stat.S_IMODE(metadata.st_mode)!=0o600 or not 1<=metadata.st_size<=maximum: raise SystemExit("topology_input_bound")
    value=path.read_bytes(); after=path.lstat()
    if (metadata.st_dev,metadata.st_ino,metadata.st_mode,metadata.st_size)!=(after.st_dev,after.st_ino,after.st_mode,after.st_size) or len(value)!=metadata.st_size: raise SystemExit("topology_input_identity")
    return value
source=bounded(config,262144).decode()
for credential in credentials: bounded(credential,4096)
relay="PHASE285_RELAY {" in source
accounts=["PHASE285_RUNTIME","PHASE285_WITNESS"]+(["PHASE285_RELAY"] if relay else [])+["PHASE285_WITNESS_STORE"]
users=["phase285_foreign","phase285_witness"]+(["phase285_relay"] if relay else [])+["phase285_witness_store","phase285_expected"]
replacements={name:f"{name}_{secrets.token_hex(16).upper()}" for name in accounts}
replacements.update({name:f"{name}_{secrets.token_hex(16)}" for name in users})
if len(replacements)!=len(accounts)+len(users) or len(set(replacements.values()))!=len(replacements): raise SystemExit("topology_probe_freshness")
value=source
for old in sorted(replacements,key=len,reverse=True):
    new=replacements[old]
    if not re.fullmatch(r"[A-Z][A-Z0-9_]*_[0-9A-F]{32}",new) and not re.fullmatch(r"[a-z0-9_]+_[0-9a-f]{32}",new): raise SystemExit("topology_probe_grammar")
    if old not in value: raise SystemExit("topology_probe_anchor")
    value=value.replace(old,new)
if any(re.search(rf"\b{re.escape(name)}\b",value) for name in accounts+users): raise SystemExit("topology_probe_canonical_identifier")
fd=os.open(probe,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
with os.fdopen(fd,"wb") as output:
    output.write(value.encode()); output.flush(); os.fsync(output.fileno())
bounded(probe,262144)
PY

  export PHASE285_TOPOLOGY_PROBE_CONFIG_PATH="$probe"
  export PHASE285_TOPOLOGY_RUST_CANONICAL_PROJECTION_PATH="$rust_canonical"
  export PHASE285_TOPOLOGY_RUST_PROBE_PROJECTION_PATH="$rust_probe"
  export PHASE285_TOPOLOGY_SHELL_CANONICAL_PROJECTION_PATH="$shell_canonical"
  export PHASE285_TOPOLOGY_SHELL_PROBE_PROJECTION_PATH="$shell_probe"
  export PHASE285_TOPOLOGY_INVOCATION_TOKEN="$token"

  topology_artifact_snapshot record "$snapshot" "$canonical:262144" "$probe:262144" \
    "${topology_snapshot_inputs[@]}"

  run_complete_receipt_focus | tee "$internal_output"
  topology_artifact_snapshot extend "$snapshot" "$canonical:262144" "$probe:262144" \
    "${topology_snapshot_inputs[@]}" \
    "$rust_canonical:16384" "$rust_probe:16384"

  python3 -I - "$canonical" "$probe" "$shell_canonical" "$shell_probe" "$tree" "$token" \
    "${topology_credential_paths[@]}" <<'PY'
import hashlib,json,os,pathlib,stat,sys
canonical,probe,shell_canonical,shell_probe=map(pathlib.Path,sys.argv[1:5]); tree,token=sys.argv[5:7]; credentials=list(map(pathlib.Path,sys.argv[7:]))
def bounded(path,maximum):
    metadata=path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode) or stat.S_IMODE(metadata.st_mode)!=0o600 or not 1<=metadata.st_size<=maximum: raise SystemExit("topology_artifact_bound")
    value=path.read_bytes(); after=path.lstat()
    if (metadata.st_dev,metadata.st_ino,metadata.st_mode,metadata.st_size)!=(after.st_dev,after.st_ino,after.st_mode,after.st_size): raise SystemExit("topology_artifact_identity")
    return value
def pairs(value,expected_accounts,expected_principals):
    owner=None; accounts=[]; result=[]
    for line in value.decode().splitlines():
        if line.startswith("  ") and not line.startswith("    ") and line.endswith(" {"):
            owner=line.strip()[:-2]; accounts.append(owner)
        elif line.strip().startswith('user: "'):
            principal=line.strip().split('"')[1]
            if owner is None: raise SystemExit("topology_shell_owner")
            result.append({"account":owner,"principal":principal})
    if len(dict.fromkeys(accounts))!=expected_accounts or len(result)!=expected_principals: raise SystemExit("topology_shell_cardinality")
    return result
canonical_bytes=bounded(canonical,262144); probe_bytes=bounded(probe,262144)
relay=b"PHASE285_RELAY {" in canonical_bytes
expected_accounts=4 if relay else 3; expected_principals=5 if relay else 4
credential_users=[]
for path in credentials:
    credential=json.loads(bounded(path,4096)); credential_users.append(credential["username"])
canonical_pairs=pairs(canonical_bytes,expected_accounts,expected_principals); probe_pairs=pairs(probe_bytes,expected_accounts,expected_principals)
if [row["principal"] for row in canonical_pairs]!=credential_users: raise SystemExit("topology_shell_credential_binding")
common={"canonical_config_sha256":hashlib.sha256(canonical_bytes).hexdigest(),"case":"service_checkpoint_topology_owner_blocks","invocation_token":token,"probe_config_sha256":hashlib.sha256(probe_bytes).hexdigest(),"schema_version":1,"tree":tree}
for path,kind,rows in [(shell_canonical,"canonical",canonical_pairs),(shell_probe,"probe",probe_pairs)]:
    value=dict(common,input_kind=kind,pairs=rows); framed=json.dumps(value,sort_keys=True,separators=(",",":")).encode()+b"\n"
    if not 1<=len(framed)<=16384: raise SystemExit("topology_projection_bound")
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(fd,"wb") as output: output.write(framed); output.flush(); os.fsync(output.fileno())
    if bounded(path,16384)!=framed: raise SystemExit("topology_projection_reopen")
PY
  topology_artifact_snapshot extend "$snapshot" "$canonical:262144" "$probe:262144" \
    "${topology_snapshot_inputs[@]}" \
    "$rust_canonical:16384" "$rust_probe:16384" "$shell_canonical:16384" "$shell_probe:16384"

  PHASE285_TOPOLOGY_CONFIG_PATH="$canonical" PHASE285_TOPOLOGY_PROBE_CONFIG_PATH="$probe" \
  PHASE285_TOPOLOGY_RUST_CANONICAL_PROJECTION_PATH="$rust_canonical" \
  PHASE285_TOPOLOGY_RUST_PROBE_PROJECTION_PATH="$rust_probe" \
  PHASE285_TOPOLOGY_SHELL_CANONICAL_PROJECTION_PATH="$shell_canonical" \
  PHASE285_TOPOLOGY_SHELL_PROBE_PROJECTION_PATH="$shell_probe" \
  PHASE285_TOPOLOGY_INVOCATION_TOKEN="$token" \
    cargo test -p swarm-governance-witness --test service_checkpoint --locked --offline -- --test-threads=1 --ignored \
      topology_validator_binds_every_tuple_to_owner_block --exact | tee "$external_output"
  python3 -I - "$external_output" <<'PY'
import re,sys
value=open(sys.argv[1],encoding="utf-8").read()
if re.findall(r"^running (\d+) test",value,re.M)!=["1"] or re.findall(r"^test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored; \d+ measured; (\d+) filtered out;",value,re.M)!=[("1","0","0","2")]: raise SystemExit("topology external transcript differs")
PY
  ci_harness_record_passed service_checkpoint \
    topology_validator_binds_every_tuple_to_owner_block "$external_output"
  topology_artifact_snapshot verify "$snapshot" "$canonical:262144" "$probe:262144" \
    "${topology_snapshot_inputs[@]}" \
    "$rust_canonical:16384" "$rust_probe:16384" "$shell_canonical:16384" "$shell_probe:16384"
  bash "$ROOT_DIR/tools/with-nats-jetstream.sh" --topology-validator "$canonical" self-test | tee "$config_output"
  topology_validator_comparator_controls "$canonical" "$topology_root" | tee "$comparator_output"
  topology_projection_controls "$canonical" "$probe" "$rust_canonical" "$rust_probe" "$shell_canonical" "$shell_probe" "$tree" "$token" "$topology_root" | tee "$projection_output"
  topology_artifact_controls "$rust_canonical" "$rust_probe" "$shell_canonical" "$shell_probe" "$topology_root" | tee -a "$projection_output"
  python3 -I - "$config_output" "$comparator_output" "$projection_output" <<'PY'
import re,sys
config,comparator,projection=[open(path,encoding="utf-8").read() for path in sys.argv[1:]]
digests=re.findall(r"digest=([0-9a-f]{64})",config)+re.findall(r"source_sha256=([0-9a-f]{64})",comparator)+re.findall(r"source_sha256=([0-9a-f]{64})",projection)
if len(digests)!=33 or len(set(digests))!=33: raise SystemExit(f"topology_mutation_digest_inventory[{len(digests)}:{len(set(digests))}]")
PY
  if [ -n "${PHASE285_RELAY_TOPOLOGY_TOKEN:-}" ]; then
    echo "topology_owner_blocks configs=2 accounts=4 principals=5 relay=1 config_mutations=23 comparator_mutations=3 projection_mutations=7 mutations=33 unique=33 vacuous=0 passed=1"
  else
    echo "topology_owner_blocks configs=2 accounts=3 principals=4 relay=0 config_mutations=23 comparator_mutations=3 projection_mutations=7 mutations=33 unique=33 vacuous=0 passed=1"
  fi
  rm -rf -- "$topology_root"
  [ ! -e "$topology_root" ] || { echo "topology route cleanup left its target behind" >&2; return 1; }
}

topology_validator_comparator_controls() {
  local canonical="$1" scratch="$2"
  python3 -I - "$ROOT_DIR/tools/with-nats-jetstream.sh" "$canonical" "$scratch" <<'PY'
import hashlib,pathlib,re,sys
harness=pathlib.Path(sys.argv[1]).read_text(); canonical=pathlib.Path(sys.argv[2]).read_text(); scratch=pathlib.Path(sys.argv[3])
start=harness.index("# PHASE285_TOPOLOGY_VALIDATOR_BEGIN")
end=harness.index("# PHASE285_TOPOLOGY_VALIDATOR_END",start)
validator=harness[start:end]
def load(source):
    namespace={"re":re,"source":canonical}; exec(source,namespace); return namespace["validate"]
current=load(validator); current(canonical)
relay="PHASE285_RELAY {" in canonical
if relay:
    import_old='account: PHASE285_RELAY, subject: "swarm.governance.witness.relay.v1.fence"'
    import_new='account: PHASE285_WITNESS_STORE, subject: "swarm.governance.witness.relay.v1.fence"'
    export_old='service: "swarm.governance.witness.v1.fence", accounts: [PHASE285_RELAY]'
else:
    import_old='account: PHASE285_WITNESS, subject: "swarm.governance.witness.v1.fence"'
    import_new='account: PHASE285_WITNESS_STORE, subject: "swarm.governance.witness.v1.fence"'
    export_old='service: "swarm.governance.witness.v1.fence", accounts: [PHASE285_RUNTIME]'
rows=[
 ("delete_response_grant_comparator",'        if row["response_grant"]!=grant: raise ValueError(f\'topology[response-grant:{row["username"]}]\')\n','',canonical.replace('allow_responses: { max: 1, expires: "12s" }','allow_responses: { max: 2, expires: "12s" }',1),"topology[response-grant:phase285_witness]"),
 ("delete_import_account_comparator",'        if graph["imports"][owner]!=expected_imports[owner]: raise ValueError(f"topology[imports:{owner}]")\n','',canonical.replace(import_old,import_new,1),"topology[imports:PHASE285_RUNTIME]"),
 ("delete_export_account_comparator",'        if graph["exports"][owner]!=expected_exports[owner]: raise ValueError(f"topology[exports:{owner}]")\n','',canonical.replace(export_old,'service: "swarm.governance.witness.v1.fence", accounts: [PHASE285_WITNESS_STORE]',1),"topology[exports:PHASE285_WITNESS]"),
]
digests=[]
for label,old,new,hostile,reason in rows:
    if validator.count(old)!=1: raise SystemExit(f"topology_comparator[{label}:anchor]")
    try: current(hostile)
    except ValueError as error:
        if str(error)!=reason: raise SystemExit(f"topology_comparator[{label}:reason:{error}]")
    else: raise SystemExit(f"topology_comparator[{label}:hostile-survived-current]")
    mutant=validator.replace(old,new,1); digests.append(hashlib.sha256(mutant.encode()).hexdigest())
    altered=load(mutant); altered(canonical); altered(hostile)
    print(f"topology_comparator_mutation mutation={label} compiled=1 canonical=passed hostile=survived intended={reason} source_sha256={digests[-1]}")
if len(set(digests))!=3: raise SystemExit("topology_comparator[digests]")
PY
}

topology_projection_controls() {
  local canonical="$1" probe="$2" rust_canonical="$3" rust_probe="$4" shell_canonical="$5" shell_probe="$6" tree="$7" token="$8" scratch="$9"
  python3 -I -u - "$ROOT_DIR" "$canonical" "$probe" "$rust_canonical" "$rust_probe" "$shell_canonical" "$shell_probe" "$tree" "$token" "$scratch" <<'PY'
import hashlib,json,os,pathlib,shutil,subprocess,sys,time
root=pathlib.Path(sys.argv[1]).resolve(); canonical_config=pathlib.Path(sys.argv[2]); probe_config=pathlib.Path(sys.argv[3])
rust_canonical,rust_probe,shell_canonical,shell_probe=map(pathlib.Path,sys.argv[4:8]); tree,token=sys.argv[8:10]; scratch=pathlib.Path(sys.argv[10])
values=[json.loads(path.read_text()) for path in [rust_canonical,rust_probe,shell_canonical,shell_probe]]
if values[0]!=values[2] or values[1]!=values[3]: raise SystemExit("topology_projection[positive]")
exact=scratch/"topology-exact-tree"; exact.mkdir()
archive=subprocess.Popen(["git","-C",str(root),"archive",tree],stdout=subprocess.PIPE)
unpack=subprocess.run(["tar","-xf","-","-C",str(exact)],stdin=archive.stdout,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,check=False)
archive.stdout.close()
if archive.wait()!=0 or unpack.returncode!=0: raise SystemExit("topology_projection[extract]")
owned=["crates/swarm-governance-witness/src/lib.rs","crates/swarm-governance-witness/tests/service_checkpoint.rs","tools/check-phase285-witness-conformance.sh","tools/fixtures/phase285-witness-integrity.json","tools/with-nats-jetstream.sh"]
for relative in owned:
    destination=exact/relative; destination.parent.mkdir(parents=True,exist_ok=True); shutil.copy2(root/relative,destination)
library=exact/"crates/swarm-governance-witness/src/lib.rs"; original=library.read_text()
def replace_once(text,old,new,label):
    if text.count(old)!=1: raise SystemExit(f"topology_projection[{label}:anchor:{text.count(old)}]")
    return text.replace(old,new,1)
relay="PHASE285_RELAY {" in canonical_config.read_text()
literal_rows=[
    ("PHASE285_RUNTIME","phase285_foreign"),
    ("PHASE285_WITNESS","phase285_witness"),
]+([("PHASE285_RELAY","phase285_relay")] if relay else [])+[
    ("PHASE285_WITNESS_STORE","phase285_witness_store"),
    ("PHASE285_WITNESS_STORE","phase285_expected"),
]
literal='        let probe_pairs = vec![\n'+''.join(
    f'            TopologyOwnerPairV1 {{ account: "{account}".to_string(), principal: "{principal}".to_string() }},\n'
    for account,principal in literal_rows
)+'        ];'
literal_source=replace_once(original,"        let probe_pairs = topology_parse_pairs(&probe, relay_expected);",literal,"rust_literal_disconnect")
swap_anchor='''        assert_eq!(
            pairs.len(),
            expected_principals,
            "topology principal cardinality"
        );
        pairs'''
swap_source=replace_once(original,swap_anchor,'''        assert_eq!(pairs.len(), expected_principals, "topology principal cardinality");
        let first_owner = pairs[0].account.clone();
        pairs[0].account = pairs[1].account.clone();
        pairs[1].account = first_owner;
        pairs''',"rust_owner_swap")
digests=[]; target=scratch/"topology-compiled-target"
base=os.environ.copy(); base["CARGO_TARGET_DIR"]=str(target); base["CARGO_NET_OFFLINE"]="true"
for label,source,reason in [("rust_literal_disconnect",literal_source,"probe parser equality"),("rust_owner_swap",swap_source,"canonical parser equality")]:
    digest=hashlib.sha256(source.encode()).hexdigest(); digests.append(digest); time.sleep(1.05); library.write_text(source)
    artifact=scratch/f"projection-{label}"; artifact.mkdir()
    env=base.copy(); env.update({
      "PHASE285_COMPLETE_RECEIPT_LEDGER_PATH":str(artifact/"ledger.json"),"PHASE285_COMPLETE_RECEIPT_PATH":str(artifact/"receipt.json"),
      "PHASE285_COMPLETE_RECEIPT_INVOCATION_TOKEN":hashlib.sha256((token+label).encode()).hexdigest(),"PHASE285_SERVICE_CHECKPOINT_TREE":tree,
      "PHASE285_TOPOLOGY_CONFIG_PATH":str(canonical_config),"PHASE285_TOPOLOGY_PROBE_CONFIG_PATH":str(probe_config),
      "PHASE285_TOPOLOGY_RUST_CANONICAL_PROJECTION_PATH":str(artifact/"rust-canonical.json"),"PHASE285_TOPOLOGY_RUST_PROBE_PROJECTION_PATH":str(artifact/"rust-probe.json"),
      "PHASE285_TOPOLOGY_SHELL_CANONICAL_PROJECTION_PATH":str(shell_canonical),"PHASE285_TOPOLOGY_SHELL_PROBE_PROJECTION_PATH":str(shell_probe),"PHASE285_TOPOLOGY_INVOCATION_TOKEN":token,
    })
    internal=["cargo","test","-p","swarm-governance-witness","--lib","--locked","--offline","--","--test-threads=1","--ignored","service_checkpoint_relay_tests::complete_receipt_authority_and_grants_are_observed","--exact"]
    print(f"topology_projection_progress control={label} phase=internal timeout_seconds=300 state=start",flush=True)
    first=subprocess.run(internal,cwd=exact,env=env,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=300)
    if first.returncode!=0 or "running 1 test" not in first.stdout or "1 passed; 0 failed" not in first.stdout: raise SystemExit(f"topology_projection[{label}:internal]\n{first.stdout}")
    print(f"topology_projection_progress control={label} phase=internal timeout_seconds=300 state=passed",flush=True)
    external=["cargo","test","-p","swarm-governance-witness","--test","service_checkpoint","--locked","--offline","--","--test-threads=1","--ignored","topology_validator_binds_every_tuple_to_owner_block","--exact"]
    print(f"topology_projection_progress control={label} phase=external timeout_seconds=300 state=start",flush=True)
    second=subprocess.run(external,cwd=exact,env=env,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=300)
    if second.returncode==0 or "running 1 test" not in second.stdout or "0 passed; 1 failed" not in second.stdout or reason not in second.stdout: raise SystemExit(f"topology_projection[{label}:external]\n{second.stdout}")
    print(f"topology_projection_progress control={label} phase=external timeout_seconds=300 state=passed",flush=True)
    print(f"topology_projection_mutation mutation={label} compiled=1 internal=1 external=1 failed=1 intended={reason} source_sha256={digest}")
library.write_text(original)
def framed(path,value):
    data=json.dumps(value,sort_keys=True,separators=(",",":")).encode()+b"\n"; path.write_bytes(data); os.chmod(path,0o600); return hashlib.sha256(data).hexdigest()
shell_value=json.loads(json.dumps(values[3])); shell_value["pairs"][0]["account"],shell_value["pairs"][1]["account"]=shell_value["pairs"][1]["account"],shell_value["pairs"][0]["account"]
shell_mutant=scratch/"shell-owner-swap.json"; digests.append(framed(shell_mutant,shell_value))
stale_rust=json.loads(json.dumps(values[0])); stale_shell=json.loads(json.dumps(values[2])); stale_rust["invocation_token"]=stale_shell["invocation_token"]="0"*64
stale_rust_path=scratch/"stale-rust.json"; stale_shell_path=scratch/"stale-shell.json"; stale_digest=framed(stale_rust_path,stale_rust)+framed(stale_shell_path,stale_shell); digests.append(hashlib.sha256(stale_digest.encode()).hexdigest())
for label,rust_can,rust_pro,shell_can,shell_pro,reason in [
 ("shell_owner_swap",rust_canonical,rust_probe,shell_canonical,shell_mutant,"probe parser equality"),
 ("stale_projection_token",stale_rust_path,rust_probe,stale_shell_path,shell_probe,"projection-token"),
]:
    env=base.copy(); env.update({"PHASE285_SERVICE_CHECKPOINT_TREE":tree,"PHASE285_TOPOLOGY_INVOCATION_TOKEN":token,"PHASE285_TOPOLOGY_CONFIG_PATH":str(canonical_config),"PHASE285_TOPOLOGY_PROBE_CONFIG_PATH":str(probe_config),"PHASE285_TOPOLOGY_RUST_CANONICAL_PROJECTION_PATH":str(rust_can),"PHASE285_TOPOLOGY_RUST_PROBE_PROJECTION_PATH":str(rust_pro),"PHASE285_TOPOLOGY_SHELL_CANONICAL_PROJECTION_PATH":str(shell_can),"PHASE285_TOPOLOGY_SHELL_PROBE_PROJECTION_PATH":str(shell_pro)})
    command=["cargo","test","-p","swarm-governance-witness","--test","service_checkpoint","--locked","--offline","--","--test-threads=1","--ignored","topology_validator_binds_every_tuple_to_owner_block","--exact"]
    print(f"topology_projection_progress control={label} phase=external timeout_seconds=120 state=start",flush=True)
    result=subprocess.run(command,cwd=exact,env=env,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=120)
    if result.returncode==0 or "running 1 test" not in result.stdout or "0 passed; 1 failed" not in result.stdout or reason not in result.stdout: raise SystemExit(f"topology_projection[{label}:external]\n{result.stdout}")
    print(f"topology_projection_progress control={label} phase=external timeout_seconds=120 state=passed",flush=True)
    source_digest=digests[2] if label=="shell_owner_swap" else digests[3]
    print(f"topology_projection_mutation mutation={label} compiled=1 external=1 failed=1 intended={reason} source_sha256={source_digest}")
if len(digests)!=4 or len(set(digests))!=4: raise SystemExit("topology_projection[digests]")
PY
}

topology_artifact_controls() {
  local rust_canonical="$1" rust_probe="$2" shell_canonical="$3" shell_probe="$4" scratch="$5"
  local label control snapshot expected output digest target replacement
  for label in projection_mode_widening projection_inode_alias projection_post_snapshot_replacement; do
    control="$scratch/$label"
    mkdir -m 700 -- "$control"
    install -m 600 -- "$rust_canonical" "$control/rust-canonical.json"
    install -m 600 -- "$rust_probe" "$control/rust-probe.json"
    install -m 600 -- "$shell_canonical" "$control/shell-canonical.json"
    install -m 600 -- "$shell_probe" "$control/shell-probe.json"
    snapshot="$control/snapshot.json"
    topology_artifact_snapshot record "$snapshot" \
      "$control/rust-canonical.json:16384" "$control/rust-probe.json:16384" \
      "$control/shell-canonical.json:16384" "$control/shell-probe.json:16384"
    topology_artifact_snapshot verify "$snapshot" \
      "$control/rust-canonical.json:16384" "$control/rust-probe.json:16384" \
      "$control/shell-canonical.json:16384" "$control/shell-probe.json:16384"
    case "$label" in
      projection_mode_widening)
        chmod 644 "$control/shell-probe.json"
        expected='topology_snapshot[mode]'
        ;;
      projection_inode_alias)
        cmp -s "$control/rust-canonical.json" "$control/shell-canonical.json" || return 1
        unlink "$control/shell-canonical.json"
        ln "$control/rust-canonical.json" "$control/shell-canonical.json"
        expected='topology_snapshot[alias]'
        ;;
      projection_post_snapshot_replacement)
        target="$control/rust-probe.json"
        replacement="$control/rust-probe.replacement"
        install -m 600 -- "$target" "$replacement"
        python3 -I - "$replacement" <<'PY'
import os,sys
descriptor=os.open(sys.argv[1],os.O_RDONLY)
try: os.fsync(descriptor)
finally: os.close(descriptor)
PY
        mv -f -- "$replacement" "$target"
        expected='topology_snapshot[changed]'
        ;;
    esac
    if output="$(topology_artifact_snapshot verify "$snapshot" \
      "$control/rust-canonical.json:16384" "$control/rust-probe.json:16384" \
      "$control/shell-canonical.json:16384" "$control/shell-probe.json:16384" 2>&1)"; then
      echo "topology artifact mutant survived: $label" >&2
      return 1
    fi
    [[ "$output" == "$expected" ]] || {
      echo "topology artifact mutant wrong reason: $label:$output" >&2
      return 1
    }
    digest="$(python3 -I - "$label" "$control/rust-canonical.json" "$control/rust-probe.json" \
      "$control/shell-canonical.json" "$control/shell-probe.json" <<'PY'
import hashlib,json,pathlib,stat,sys
rows=[]
for raw in sys.argv[2:]:
    path=pathlib.Path(raw); metadata=path.lstat(); value=path.read_bytes()
    rows.append({"device":metadata.st_dev,"inode":metadata.st_ino,"length":len(value),"mode":stat.S_IMODE(metadata.st_mode),"sha256":hashlib.sha256(value).hexdigest()})
framed=json.dumps({"label":sys.argv[1],"rows":rows},sort_keys=True,separators=(",",":")).encode()
print(hashlib.sha256(framed).hexdigest())
PY
)"
    [[ "$digest" =~ ^[0-9a-f]{64}$ ]] || return 1
    echo "topology_projection_mutation mutation=$label compiled=1 flow=1 fs_mutation=1 failed=1 intended=$expected source_sha256=$digest"
  done
}

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
  python3 -I - "$list_output" "$inventory_file" <<'PY'
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
  local -a case_args
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
    case "$case_name" in
      jetstream_cas_rejects_wrong_revision_header_or_ack|jetstream_cas_confirms_raw_sequence_and_bytes|jetstream_cas_rejects_del_purge_rollup_and_direct_reads|jetstream_checkpoint_*|full_service_path_rejects_runtime_private_subject_and_store_raw_api|full_service_path_rejects_credential_account_and_mount_swaps|full_service_path_validates_proxy_response_before_public_attestation|full_service_path_fails_closed_on_store_queue_exhaustion|production_initializer_creates_reopens_and_reproduces_ready)
        case_args=(-- --ignored "$case_name" --exact)
        ;;
      *)
        case_args=(-- "$case_name" --exact)
        ;;
    esac
    if [ "$selector" = jetstream-cas ]; then
      expected_inner="$temp_dir/$case_name.expected.tsv"
      inner_ledger="$temp_dir/$case_name.ledger.tsv"
      [ ! -e "$inner_ledger" ] || return 1
      write_expected_inner_ledger "$case_name" "$expected_inner"
      if ! PHASE285_WITNESS_INNER_LEDGER_REQUIRED=1 \
        PHASE285_WITNESS_INNER_LEDGER="$inner_ledger" \
        PHASE285_CHECKPOINT_LEDGER_REQUIRED=1 \
        PHASE285_CHECKPOINT_LEDGER="$inner_ledger" \
        cargo test -p "$package" --test "$target" --locked --offline "${case_args[@]}" >"$output_file" 2>&1; then
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
        cargo test -p "$package" --test "$target" --locked --offline "${case_args[@]}" >"$output_file" 2>&1; then
        cat "$output_file" >&2
        echo "named case failed: selector=$selector case=$case_name" >&2
        return 1
      fi
    elif [ "$selector" = public-dispatcher ] && [ "$executed" -eq 0 ]; then
      if ! PHASE285_DISPATCHER_MAPPING_LEDGER_REQUIRED=1 \
        PHASE285_DISPATCHER_MAPPING_LEDGER="$observed_union" \
        cargo test -p "$package" --test "$target" --locked --offline "${case_args[@]}" >"$output_file" 2>&1; then
        cat "$output_file" >&2
        echo "named case failed: selector=$selector case=$case_name" >&2
        return 1
      fi
    elif [ "$selector" = full-service-path ]; then
      if ! PHASE285_CAPABILITY_MATRIX_LEDGER_REQUIRED=1 \
        PHASE285_CAPABILITY_MATRIX_LEDGER="$observed_union" \
        PHASE285_CAPABILITY_MATRIX_INVOCATION_TOKEN="$capability_invocation_token" \
        cargo test -p "$package" --test "$target" --locked --offline "${case_args[@]}" >"$output_file" 2>&1; then
        cat "$output_file" >&2
        echo "named case failed: selector=$selector case=$case_name" >&2
        return 1
      fi
    elif ! cargo test -p "$package" --test "$target" --locked --offline "${case_args[@]}" >"$output_file" 2>&1; then
      cat "$output_file" >&2
      echo "named case failed: selector=$selector case=$case_name" >&2
      return 1
    fi
    python3 -I - "$output_file" "$case_name" "$expected_filtered" <<'PY'
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
    case "$case_name" in
      jetstream_cas_rejects_wrong_revision_header_or_ack|jetstream_cas_confirms_raw_sequence_and_bytes|jetstream_cas_rejects_del_purge_rollup_and_direct_reads)
        ci_harness_record_passed jetstream_cas "$case_name" "$output_file"
        ;;
      jetstream_checkpoint_*)
        ci_harness_record_passed jetstream_checkpoint "$case_name" "$output_file"
        ;;
      full_service_path_rejects_runtime_private_subject_and_store_raw_api|full_service_path_rejects_credential_account_and_mount_swaps|full_service_path_validates_proxy_response_before_public_attestation|full_service_path_fails_closed_on_store_queue_exhaustion|production_initializer_creates_reopens_and_reproduces_ready)
        ci_harness_record_passed full_service_path "$case_name" "$output_file"
        ;;
    esac
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
  cleanup_temp_dir
  trap - EXIT
}

validate_service_checkpoint_exact_test() {
  local transcript="$1" inventory="$2" expected_fqn="$3" expected_marker="$4"
  python3 -I - "$transcript" "$inventory" "$expected_fqn" "$expected_marker" <<'PY'
import pathlib, re, sys
text = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
inventory = []
for line in pathlib.Path(sys.argv[2]).read_text(encoding="utf-8").splitlines():
    match = re.fullmatch(r"([^:]+(?:::[^:]+)*): test", line)
    if match:
        inventory.append(match.group(1))
expected_fqn, marker = sys.argv[3:]
if len(inventory) != len(set(inventory)) or inventory.count(expected_fqn) != 1:
    raise SystemExit("service checkpoint compiled test inventory differs")
expected_filtered = str(len(inventory) - 1)
running = re.findall(r"^running (\d+) test$", text, re.MULTILINE)
summary = re.findall(r"^test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out;", text, re.MULTILINE)
if running != ["1"] or summary != [("1", "0", "0", "0", expected_filtered)]:
    raise SystemExit("service checkpoint live transcript counts differ")
if text.count(marker) != 1:
    raise SystemExit("service checkpoint live transcript marker differs")
PY
}

validate_service_checkpoint_grant_ledger() {
  local ledger="$1" tree="$2" mode="$3"
  python3 -I - "$ledger" "$tree" "$mode" <<'PY'
import hashlib, json, pathlib, re, sys
path, tree, mode = pathlib.Path(sys.argv[1]), sys.argv[2], sys.argv[3]
raw = path.read_bytes()
def reject(value): raise ValueError(value)
def canonical(value): return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
if not raw.endswith(b"\n") or raw.count(b"\n") != 1:
    raise SystemExit("response_grant[framing]")
value = json.loads(raw[:-1], parse_constant=reject)
if canonical(value) + b"\n" != raw:
    raise SystemExit("response_grant[canonical]")
if value.get("schema_version") != 1 or value.get("tree") != tree or value.get("case") != "service_checkpoint_response_grants" or value.get("mode") != mode:
    raise SystemExit("response_grant[identity]")
if mode == "normal":
    if value.get("invocation_token") != "normal-" + tree:
        raise SystemExit("response_grant[token]")
else:
    token = value.get("invocation_token", "")
    if not re.fullmatch(r"relay-phase285-[A-Za-z0-9._-]+", token) or len(token) > 512:
        raise SystemExit("response_grant[token]")
rows = value.get("rows")
if not isinstance(rows, list) or [row.get("label") for row in rows] != ["private", "public"]:
    raise SystemExit("response_grant[rows]")
expected = {
    "private": (3000, 2500, 3500, "PHASE285_WITNESS_STORE", "witness-store"),
    "public": (12000, 10500, 12500, "PHASE285_RELAY" if mode == "relay" else "PHASE285_WITNESS", "relay" if mode == "relay" else "witness"),
}
ids = set()
for row in rows:
    grant, accepted, rejected, account, user = expected[row["label"]]
    if (row.get("grant_millis"), row.get("accepted_delay_millis"), row.get("rejected_delay_millis")) != (grant, accepted, rejected):
        raise SystemExit("response_grant[schedule]")
    first, second, delta = row.get("first_response_enqueue_started_at_micros"), row.get("second_response_enqueue_started_at_micros"), row.get("second_response_enqueue_start_delta_micros")
    if not all(isinstance(item, int) for item in (first, second, delta)) or first < accepted * 1000 or second - first != delta or not 0 <= delta < 50000 or second >= grant * 1000:
        raise SystemExit("response_grant[enqueue-start-timing]")
    if row.get("response_grant_expires_at_micros") != grant * 1000 or row.get("requester_response_count") != 1 or row.get("delayed_control_enqueue_start_delta_micros", 0) < 50000:
        raise SystemExit("response_grant[grant-bound]")
    for name in ("maximum_rejection", "expiry_rejection", "delayed_control_rejection"):
        event = row.get(name, "")
        if "Permissions Violation for Publish to" not in event:
            raise SystemExit("response_grant[server-refusal]")
    for connection_name in ("responder_connection", "requester_connection"):
        connection = row.get(connection_name, {})
        client_id = connection.get("server_client_id")
        if not isinstance(client_id, int) or client_id <= 0 or client_id in ids:
            raise SystemExit("response_grant[connection-id]")
        ids.add(client_id)
        evidence = bytes.fromhex(connection.get("server_evidence_canonical_hex", ""))
        if hashlib.sha256(evidence).hexdigest() != connection.get("server_evidence_sha256"):
            raise SystemExit("response_grant[server-evidence-digest]")
        decoded = json.loads(evidence, parse_constant=reject)
        if canonical(decoded) != evidence or decoded.get("server_client_id") != client_id or decoded.get("account") != connection.get("account") or decoded.get("authenticated_user") != connection.get("authenticated_user"):
            raise SystemExit("response_grant[server-evidence]")
    responder = row["responder_connection"]
    if responder.get("account") != account or responder.get("authenticated_user") != ("phase285_relay" if user == "relay" else "phase285_witness_store" if user == "witness-store" else "phase285_witness"):
        raise SystemExit("response_grant[responder-authority]")
print("service_checkpoint_grants rows=2 private_grant_millis=3000 public_grant_millis=12000 max_responses=1 timing_controls=2 passed=1")
PY
}

transport_semantics_source_guard() {
  python3 -I - "$ROOT_DIR/crates/swarm-governance-witness/src/runtime_client.rs" \
    "$ROOT_DIR/crates/swarm-governance-witness/src/service_config.rs" \
    "$ROOT_DIR/crates/swarm-governance-witness/src/public_dispatcher.rs" \
    "$ROOT_DIR/crates/swarm-governance-witness/src/store_proxy_service.rs" \
    "$ROOT_DIR/crates/swarm-governance-witness/src/lib.rs" "${1:-normal}" <<'PY'
import hashlib,pathlib,sys
paths=list(map(pathlib.Path,sys.argv[1:6])); mode=sys.argv[6]
names=["runtime","config","public","private","library"]
source=dict(zip(names,(path.read_text() for path in paths)))
def exact(text,fragment,label):
 if text.count(fragment)!=1: raise ValueError(label)
def validate(value):
 runtime,config,public,private,library=[value[name] for name in names]
 exact(runtime,"async_nats::RequestErrorKind::TimedOut => RuntimeWitnessClientErrorV1::OutcomeUnknown,","timed_out_mapping")
 exact(runtime,"async_nats::RequestErrorKind::Other => RuntimeWitnessClientErrorV1::OutcomeUnknown,","other_mapping")
 exact(runtime,"async_nats::RequestErrorKind::NoResponders => RuntimeWitnessClientErrorV1::Unavailable,","no_responders_mapping")
 exact(runtime,"async_nats::RequestErrorKind::InvalidSubject => RuntimeWitnessClientErrorV1::Configuration,","invalid_subject_mapping")
 exact(config,"ResponseDeadlineCheck {\n        worker: WorkerKindV1,\n        open: bool,\n    },\n    #[serde(rename = \"response_enqueue_attempt\")]\n    ResponseEnqueueAttempt {\n        worker: WorkerKindV1,\n        enqueued: bool,\n    },","enqueue_event")
 exact(config,"let notified = self.reached_notify.notified();\n            if self.reached.load(Ordering::SeqCst) {\n                return;\n            }\n            notified.await;","predicate_backed_poll_gate")
 if "PublishAttempt" in config or "published: bool" in config: raise ValueError("published_claim")
 exact(public,"gate.before_first_poll(expected_subject).await;\n        }\n        while let Some(message) = subscriber.next().await","public_pre_poll_gate")
 exact(private,"gate.before_first_poll(subject).await;\n                }\n                while let Some(message) = subscriber.next().await","private_pre_poll_gate")
 exact(public,"message.receipt_deadline,\n        observer,","public_receipt_deadline")
 exact(private,"message.receipt_deadline,\n        observer,","private_receipt_deadline")
 exact(private,".map_err(|_| PublicWitnessProxyTransportErrorV1::OutcomeUnknown)?","private_outer_timeout_outcome_unknown")
 exact(public,"PublicWitnessProxyTransportErrorV1::Timeout => PublicWitnessDispatchErrorV1::OutcomeUnknown,","dispatcher_timeout_outcome_unknown")
 if "PublicWitnessProxyTransportErrorV1::Timeout => PublicWitnessDispatchErrorV1::Timeout" in public: raise ValueError("dispatcher_timeout_exposure")
 request_observed=runtime.split("    async fn request_observed(",1)[1].split("\n    async fn request_transport(",1)[0]
 request_transport=runtime.split("    async fn request_transport(",1)[1].split("\n    #[cfg(test)]\n    pub(crate) async fn observe_transport_message_for_test(",1)[0]
 for fragment,label in [
  ("let deadline =\n            TokioInstant::now() + Duration::from_millis(self.config.request_deadline_millis);","api_entry_deadline"),
  (".request_transport(\n                PublicWitnessServiceConfigV1::subject_for(request.operation),\n                bytes,\n                deadline,","deadline_forwarding"),
  ("if TokioInstant::now() >= deadline","deadline_processing_checks"),
 ]:
  if request_observed.count(fragment)<1: raise ValueError(label)
 exact(request_transport,"deadline: TokioInstant,","transport_absolute_deadline")
 exact(request_transport,"let remaining = deadline.saturating_duration_since(TokioInstant::now());","transport_remaining_budget")
 exact(request_transport,".timeout(Some(remaining));","transport_request_remaining_budget")
 exact(request_transport,"timeout_at(\n            deadline,\n            self.client.send_request(subject.to_owned(), request),\n        )","transport_outer_deadline")
 exact(library,"matches!(first, Err(RuntimeWitnessClientErrorV1::OutcomeUnknown)),\n            \"expired response grant was not requester-observed OutcomeUnknown: {leg:?}\"","post_grant_outcome")
 exact(library,"tokio::time::sleep(Duration::from_millis(grant_millis + 250)).await;","grant_expiry_hold")
 exact(library,"atomic_records_after_stale.len(),\n            atomic_records_before_stale.len(),\n            \"recovery[stale-private-no-second-cas-record]\"","stale_no_second_cas_record")
 exact(library,"atomic_records_digest_after_stale, atomic_records_digest_before_stale,\n            \"recovery[stale-private-atomic-record-unchanged]\"","stale_atomic_record_unchanged")
 exact(library,"verified_attempts - post_recovery_attempts,\n                verified_applied - post_recovery_applied,\n            ),\n            (0, 0),\n            \"recovery[stale-private-atomic-delta]\"","stale_atomic_delta")
 exact(library,"let (replay_one, replay_one_bytes) = must(\n            runtime_client\n                .observe_response_bytes_for_test(&request)","replay_one_runtime_bytes")
 exact(library,"assert_eq!(replay_one_capture.payload, replay_one_bytes);","replay_one_capture_bytes")
 exact(library,"let (replay_two, replay_two_bytes) = must(\n            runtime_client\n                .observe_response_bytes_for_test(&request)","replay_two_runtime_bytes")
 exact(library,"assert_eq!(replay_two_capture.payload, replay_two_bytes);","replay_two_capture_bytes")
 exact(library,"replay_one_bytes, replay_two_bytes,\n            \"response grant authenticated public replays differ\"","public_replay_byte_equality")
 exact(library,"permission_violation.contains(\"Permissions Violation for Publish to\")","broker_late_publish_refusal")
 exact(library,"permission_event(&mut witness_events, &targeted_receipt.reply).await","public_reply_binding")
 exact(library,"permission_event(&mut store_events, &targeted_receipt.reply).await","private_reply_binding")
 exact(library,"!permission_violation.contains(unrelated_reply)","unrelated_refusal_control")
 shared=private.split("    async fn request_bytes_on_subject(",1)[1].split("\n    #[cfg(test)]\n    pub(crate) async fn request_on_subject_for_test(",1)[0]
 exact(shared,"if request_bytes.len() > self.max_request_bytes","shared_request_bound")
 exact(shared,"if message.payload.len() > self.max_response_bytes","shared_response_bound")
 exact(shared,"WitnessStoreProxyResponseV1::decode(&message.payload)","shared_response_decode")
 exact(shared,"if response.operation != operation || response.request_digest != request_digest {","shared_response_binding")
 exact(private,"self.request_bytes_on_subject(bytes, operation, subject, &request_digest)","production_shared_request_path")
 exact(private,"request_bytes.to_vec(),","replay_original_bytes")
 exact(library,"record.cas_applied != result_applied","cas_evidence_reconciliation")
validate(source)
if mode=="self-test":
 mutations=[
  ("other_to_unavailable","runtime","async_nats::RequestErrorKind::Other => RuntimeWitnessClientErrorV1::OutcomeUnknown,","async_nats::RequestErrorKind::Other => RuntimeWitnessClientErrorV1::Unavailable,"),
  ("no_responders_to_outcome_unknown","runtime","async_nats::RequestErrorKind::NoResponders => RuntimeWitnessClientErrorV1::Unavailable,","async_nats::RequestErrorKind::NoResponders => RuntimeWitnessClientErrorV1::OutcomeUnknown,"),
  ("post_grant_success_fabrication","library","GrantExpiryLegV1::Public => {\n                    permission_event(&mut witness_events, &targeted_receipt.reply).await\n                }\n                GrantExpiryLegV1::Private => {\n                    permission_event(&mut store_events, &targeted_receipt.reply).await\n                }","GrantExpiryLegV1::Public => {\n                    next_publish_permission_violation(&mut witness_events).await\n                }\n                GrantExpiryLegV1::Private => {\n                    next_publish_permission_violation(&mut store_events).await\n                }"),
  ("reset_local_deadline_after_dequeue","public","message.receipt_deadline,\n        observer,\n        publisher,\n        message.reply,\n        |_| {\n            dispatcher.dispatch_before(&message.subject, &message.payload, message.receipt_deadline)\n        },","ReceiptDeadlineV1::public(),\n        observer,\n        publisher,\n        message.reply,\n        |_| {\n            dispatcher.dispatch_before(&message.subject, &message.payload, ReceiptDeadlineV1::public())\n        },"),
  ("omit_public_pre_poll_hold","public","gate.before_first_poll(expected_subject).await;","tokio::task::yield_now().await;"),
  ("omit_private_pre_poll_hold","private","gate.before_first_poll(subject).await;","tokio::task::yield_now().await;"),
  ("bypass_shared_response_binding","private","if response.operation != operation || response.request_digest != request_digest {","if false {"),
  ("outer_timeout_to_timeout","private",".map_err(|_| PublicWitnessProxyTransportErrorV1::OutcomeUnknown)?",".map_err(|_| PublicWitnessProxyTransportErrorV1::Timeout)?"),
  ("dispatcher_timeout_to_timeout","public","PublicWitnessProxyTransportErrorV1::Timeout => PublicWitnessDispatchErrorV1::OutcomeUnknown,","PublicWitnessProxyTransportErrorV1::Timeout => PublicWitnessDispatchErrorV1::Timeout,"),
  ("restore_lost_wakeup","config","let notified = self.reached_notify.notified();\n            if self.reached.load(Ordering::SeqCst) {\n                return;\n            }\n            notified.await;","if self.reached.load(Ordering::SeqCst) {\n                return;\n            }\n            self.reached_notify.notified().await;"),
  ("retain_published_true","config","    OutcomeUnknown,","    PublishAttempt { worker: WorkerKindV1, published: bool },\n    OutcomeUnknown,"),
 ]
 digests=[]
 for label,name,old,new in mutations:
  if source[name].count(old)!=1: raise SystemExit("transport_semantics_source[anchor:"+label+"]")
  candidate=dict(source); candidate[name]=candidate[name].replace(old,new,1)
  digest=hashlib.sha256(candidate[name].encode()).hexdigest(); digests.append(digest)
  try: validate(candidate)
  except ValueError as error: print(f"transport_semantics_mutation mutation={label} rejected={error} source_sha256={digest}")
  else: raise SystemExit("transport_semantics_source[survived:"+label+"]")
 if len(set(digests))!=len(mutations): raise SystemExit("transport_semantics_source[digests]")
 print(f"transport_semantics_source mutations={len(mutations)} unique={len(set(digests))} vacuous=0 passed=1")
PY
}

transport_semantics_registry_guard() {
  python3 -I - "${1:-}" <<'PY'
import hashlib,json,os,pathlib,sys

T="service_checkpoint_transport_semantics_tests::post_command_other_is_distinct_from_pre_send_drain"
G="service_checkpoint_transport_semantics_tests::public_and_private_expired_response_grants_recover_exactly_once"

def row(control_id,target,case,source_path,anchor,replacement,predicate):
    command=["cargo","test","-p","swarm-governance-witness","--lib","--locked","--offline",target,"--","--ignored","--exact","--nocapture","--test-threads=1"]
    if case is not None:
        command=["env",f"PHASE285_R1A_GRANT_CASE={case}",*command]
    mutation_spec={
        "id":control_id,
        "target":target,
        "physical_case":case,
        "source_path":source_path,
        "source_anchor":anchor,
        "replacement":replacement,
        "late_failure_predicate":predicate,
    }
    mutation_spec_bytes=json.dumps(mutation_spec,sort_keys=True,separators=(",",":"),allow_nan=False).encode()
    return {
        "id":control_id,
        "target":target,
        "physical_case":case,
        "source_path":source_path,
        "source_anchor":anchor,
        "replacement":replacement,
        "late_failure_predicate":predicate,
        "exact_command":command,
        "mutation_spec_sha256":hashlib.sha256(mutation_spec_bytes).hexdigest(),
        "mutated_source_sha256":None,
        "selected_executable_sha256":None,
        "execution_status":"executable_pending_run" if case is None else "red_registry_only",
        "real_target_classification":{
            "exact_fqn_required":True,
            "exact_physical_case_required":case is not None,
            "required_running_count":1,
            "required_failed_count":1,
            "required_passed_count":0,
        },
        "vacuity_classification":{
            "compile_failure":"vacuous",
            "zero_tests":"vacuous",
            "timeout":"vacuous",
            "generic_failure":"vacuous",
            "failure_before_named_predicate":"vacuous",
            "helper_authored_success":"vacuous",
            "named_late_predicate":"required",
        },
    }

rows=[
 row("R1A-C01",T,None,"crates/swarm-governance-witness/src/runtime_client.rs","runtime `Other -> OutcomeUnknown`","`Other -> Unavailable`","transport[post-command-other-outcome-unknown]"),
 row("R1A-C02",T,None,"crates/swarm-governance-witness/src/runtime_client.rs","runtime `NoResponders -> Unavailable`","`NoResponders -> OutcomeUnknown`","transport[no-responders-unavailable]"),
 row("R1A-C03",G,"held-public","crates/swarm-governance-witness/src/lib.rs","targeted reply-subject permission-event match","accept next unrelated permission event","grant[targeted-public-refusal]"),
 row("R1A-C04",G,"held-public","crates/swarm-governance-witness/src/public_dispatcher.rs","receipt deadline carried from subscriber admission","construct a fresh deadline after dequeue","deadline[admission-anchor-preserved]"),
 row("R1A-C05",G,"held-public","crates/swarm-governance-witness/src/public_dispatcher.rs","public `before_first_poll` gate","no-op yield","grant[public-pre-poll-gate-reached]"),
 row("R1A-C06",G,"held-private","crates/swarm-governance-witness/src/store_proxy_service.rs","private `before_first_poll` gate","no-op yield","grant[private-pre-poll-gate-reached]"),
 row("R1A-C07",G,"held-private","crates/swarm-governance-witness/src/store_proxy_service.rs","exact replayed signed private CAS returns request-bound service-level `Refused(Conflict)` before atomic CAS","proxy client rewrites that response as `CasApplied`","recovery[stale-private-conflict]"),
 row("R1A-C08",G,"held-public","crates/swarm-governance-witness/src/service_config.rs","`ResponseEnqueueAttempt { enqueued }` evidence","`PublishAttempt { published }` evidence","evidence[enqueue-not-publication]"),
 row("R1A-C09",T,None,"crates/swarm-governance-witness/src/lib.rs","relay principal on exact routed Fence subject","witness principal on ordinary Fence subject","transport[relay-routed-responder]"),
 row("R1A-C10",G,"held-public","crates/swarm-governance-witness/src/lib.rs","observed nine flushed public relay subscriptions and three flushed private relay subscriptions","omit only the nine public subscriptions while retaining and flushing all three private subscriptions","relay[public-route-ready]"),
 row("R1A-C11",G,"held-private","crates/swarm-governance-witness/src/lib.rs","observed nine flushed public relay subscriptions and three flushed private relay subscriptions","omit only the three private subscriptions while retaining and flushing all nine public subscriptions","relay[private-route-ready]"),
 row("R1A-C12",T,None,"crates/swarm-governance-witness/src/store_proxy_service.rs","private `InvalidSubject -> Framing/Invalid`","`InvalidSubject -> Unavailable`","private[invalid-subject-invalid]"),
 row("R1A-C13",T,None,"crates/swarm-governance-witness/src/public_dispatcher.rs","dispatcher `Framing -> Invalid`","`Framing -> Unavailable`","private[framing-invalid]"),
 row("R1A-C14",T,None,"crates/swarm-governance-witness/src/store_proxy_service.rs","malformed private response decode rejection","accept default response","private[malformed-response-invalid]"),
 row("R1A-C15",T,None,"crates/swarm-governance-witness/src/store_proxy_service.rs","exact private response operation equality","accept mismatched operation","private[operation-mismatch-invalid]"),
 row("R1A-C16",T,None,"crates/swarm-governance-witness/src/store_proxy_service.rs","exact private response request-digest equality","accept mismatched digest","private[request-digest-mismatch-invalid]"),
 row("R1A-C17",G,"held-public","crates/swarm-governance-witness/src/lib.rs","operand receipt `public_pre_enqueue_capture(capture_id,digest)` vs `runtime_recovery_1(digest)`","`runtime_recovery_1` vs `runtime_recovery_2`","recovery[public-lost-replay-operands]"),
 row("R1A-C18",G,"held-private","crates/swarm-governance-witness/src/lib.rs","execute the private-response/CAS/store/final-read transitive validator","bypass that validator; the unchanged target's hostile cross-wired private capture must then survive","recovery[private-cas-binding-required]"),
 row("R1A-C19",G,"held-private","crates/swarm-governance-witness/src/lib.rs","layer-relative receipt/snapshot join","directly assert private `CasApplied` bytes equal outer public `Establish` bytes","recovery[cross-layer-bytes-differ]"),
 row("R1A-C20",G,"no-hold-public","crates/swarm-governance-witness/src/lib.rs","parent awaits and consumes typed child result, then writes bound later parent-join record","drop/detach handle and set marker true","no-hold[public-parent-join-consumed]"),
 row("R1A-C21",G,"no-hold-private","crates/swarm-governance-witness/src/lib.rs","parent awaits and consumes typed child result, then writes bound later parent-join record","drop/detach handle and set marker true","no-hold[private-parent-join-consumed]"),
 row("R1A-C22",G,"held-public","crates/swarm-governance-witness/src/lib.rs","real public pre-enqueue observer capture","no-op observer plus recovery-derived substitute bytes","capture[public-first-payload-real]"),
 row("R1A-C23",G,"held-private","crates/swarm-governance-witness/src/lib.rs","real private pre-enqueue observer capture","no-op observer plus request-derived substitute `CasApplied` bytes","capture[private-first-payload-real]"),
]

no_hold_join_anchor='''            let first = must(
                tokio::time::timeout(
                    Duration::from_millis(PUBLIC_RESPONSE_GRANT_MILLIS + 2_000),
                    first,
                )
                .await,
                "no-hold response grant request timeout",
            );
            let (response, response_bytes, child_receipt) = must(
                must(first, "no-hold response grant request task panicked"),
                "no-hold response grant requester response",
            );
            assert!(
                matches!(response, WitnessServiceResponseV1::Establish(_)),
                "no-hold response grant returned the wrong response variant: {leg:?}",
            );
            let private_capture = if let Some(receipt) = private_receipt.as_ref() {
                Some(must(
                    targeted_response_capture(
                        &mut capture_rx,
                        WorkerKindV1::Private,
                        &receipt.reply,
                    )
                    .await,
                    "no-hold private response capture",
                ))
            } else {
                None
            };
            let public_capture = must(
                targeted_response_capture(
                    &mut capture_rx,
                    WorkerKindV1::Public,
                    &public_receipt.reply,
                )
                .await,
                "no-hold response grant first payload capture",
            );
            assert_eq!(public_capture.receipt.invocation_token, relay_token);
            assert_eq!(public_capture.receipt.physical_case, physical_case);
            let parent_receipt = requester_ledger.record_parent(
                &relay_token,
                physical_case,
                &child_task_id,
                &child_receipt,
                &response_bytes,
            );
            let parent_join_bound = requester_ledger.contains_parent(&parent_receipt)
                && parent_receipt.parent_sequence > child_receipt.child_sequence
                && parent_receipt.returned_response_sha256 == sha256_hex(&response_bytes);'''

no_hold_detach_template='''            assert!(
                matches!(leg, GrantExpiryLegV1::__LEG__),
                "no-hold detached control physical case",
            );
            let _fabricated_parent_marker = "__MARKER__";
            drop(first);
            let private_capture = if let Some(receipt) = private_receipt.as_ref() {
                Some(must(
                    targeted_response_capture(
                        &mut capture_rx,
                        WorkerKindV1::Private,
                        &receipt.reply,
                    )
                    .await,
                    "no-hold private response capture",
                ))
            } else {
                None
            };
            let public_capture = must(
                targeted_response_capture(
                    &mut capture_rx,
                    WorkerKindV1::Public,
                    &public_receipt.reply,
                )
                .await,
                "no-hold response grant first payload capture",
            );
            assert_eq!(public_capture.receipt.invocation_token, relay_token);
            assert_eq!(public_capture.receipt.physical_case, physical_case);
            let response_bytes = public_capture.payload.clone();
            let response = must(
                WitnessServiceResponseV1::decode_for_client_request(&response_bytes, &request),
                "no-hold detached response decode",
            );
            assert!(
                matches!(response, WitnessServiceResponseV1::Establish(_)),
                "no-hold response grant returned the wrong response variant: {leg:?}",
            );
            let child_receipt = must(
                tokio::time::timeout(Duration::from_secs(2), async {
                    loop {
                        let recorded = {
                            requester_ledger
                                .rows
                                .lock()
                                .unwrap_or_else(std::sync::PoisonError::into_inner)
                                .iter()
                                .find_map(|row| match row {
                                    RequesterJoinLedgerRowV1::Child(receipt)
                                        if receipt.child_task_id == child_task_id =>
                                    {
                                        Some(receipt.clone())
                                    }
                                    _ => None,
                                })
                        };
                        if let Some(receipt) = recorded {
                            break receipt;
                        }
                        tokio::task::yield_now().await;
                    }
                })
                .await,
                "no-hold detached child terminal receipt absent",
            );
            let parent_receipt = RequesterParentJoinReceiptV1 {
                invocation_token: relay_token.clone(),
                physical_case: physical_case.to_string(),
                child_task_id: child_task_id.clone(),
                child_record_sha256: sha256_hex(&must(
                    canonical_wire_bytes(&child_receipt),
                    "no-hold fabricated parent child receipt bytes",
                )),
                returned_response_sha256: sha256_hex(&response_bytes),
                parent_sequence: child_receipt.child_sequence.saturating_add(1),
            };
            let parent_join_bound = requester_ledger.contains_parent(&parent_receipt)
                && parent_receipt.parent_sequence > child_receipt.child_sequence
                && parent_receipt.returned_response_sha256 == sha256_hex(&response_bytes);'''

executable_specs={
 "transport[post-command-other-outcome-unknown]":(
  "async_nats::RequestErrorKind::Other => RuntimeWitnessClientErrorV1::OutcomeUnknown,",
  "async_nats::RequestErrorKind::Other => RuntimeWitnessClientErrorV1::Unavailable,",
 ),
 "transport[no-responders-unavailable]":(
  "async_nats::RequestErrorKind::NoResponders => RuntimeWitnessClientErrorV1::Unavailable,",
  "async_nats::RequestErrorKind::NoResponders => RuntimeWitnessClientErrorV1::OutcomeUnknown,",
 ),
 "transport[relay-routed-responder]":(
  '''        let relay = must(
            connect_deadline_role("SWARM_NATS_RELAY_CREDENTIAL_PATH", "relay").await,
            "transport Other relay connection",
        );
        let subject = PublicWitnessServiceConfigV1::subject_for(WitnessServiceOperationV1::Fence);
        let responder_subject = "swarm.governance.witness.relay.v1.fence";''',
  '''        let relay = must(
            connect_deadline_role("SWARM_NATS_WITNESS_CREDENTIAL_PATH", "witness").await,
            "transport Other relay connection",
        );
        let subject = PublicWitnessServiceConfigV1::subject_for(WitnessServiceOperationV1::Fence);
        let responder_subject = subject;''',
 ),
 "private[invalid-subject-invalid]":(
  "async_nats::RequestErrorKind::InvalidSubject => PublicWitnessProxyTransportErrorV1::Framing,",
  "async_nats::RequestErrorKind::InvalidSubject => PublicWitnessProxyTransportErrorV1::Unavailable,",
 ),
 "private[framing-invalid]":(
  "PublicWitnessProxyTransportErrorV1::Framing => PublicWitnessDispatchErrorV1::Invalid,",
  "PublicWitnessProxyTransportErrorV1::Framing => PublicWitnessDispatchErrorV1::Unavailable,",
 ),
 "private[malformed-response-invalid]":(
  '''        let response = WitnessStoreProxyResponseV1::decode(&message.payload)
            .map_err(|_| PublicWitnessProxyTransportErrorV1::Framing)?;
        if response.operation != operation || response.request_digest != request_digest {
            return Err(PublicWitnessProxyTransportErrorV1::Framing);
        }
        Ok(response)
    }

    #[cfg(test)]
    pub(crate) async fn request_on_subject_for_test''',
  '''        let response = match WitnessStoreProxyResponseV1::decode(&message.payload) {
            Ok(response) => response,
            Err(_) => WitnessStoreProxyResponseV1 {
                schema_version: PROTOCOL_SCHEMA_VERSION,
                operation,
                request_digest: request_digest.clone(),
                body: WitnessStoreProxyResponseBodyV1::Refused {
                    failure_code: WitnessStoreProxyFailureCodeV1::Configuration,
                    observed_revision: None,
                    observed_value_digest: None,
                },
            },
        };
        if response.operation != operation || response.request_digest != request_digest {
            return Err(PublicWitnessProxyTransportErrorV1::Framing);
        }
        Ok(response)
    }

    #[cfg(test)]
    pub(crate) async fn request_on_subject_for_test''',
 ),
 "private[operation-mismatch-invalid]":(
  '''        let response = WitnessStoreProxyResponseV1::decode(&message.payload)
            .map_err(|_| PublicWitnessProxyTransportErrorV1::Framing)?;
        if response.operation != operation || response.request_digest != request_digest {
            return Err(PublicWitnessProxyTransportErrorV1::Framing);
        }
        Ok(response)
    }

    #[cfg(test)]
    pub(crate) async fn request_on_subject_for_test''',
  '''        let response = WitnessStoreProxyResponseV1::decode(&message.payload)
            .map_err(|_| PublicWitnessProxyTransportErrorV1::Framing)?;
        if response.request_digest != request_digest {
            return Err(PublicWitnessProxyTransportErrorV1::Framing);
        }
        Ok(response)
    }

    #[cfg(test)]
    pub(crate) async fn request_on_subject_for_test''',
 ),
 "private[request-digest-mismatch-invalid]":(
  '''        let response = WitnessStoreProxyResponseV1::decode(&message.payload)
            .map_err(|_| PublicWitnessProxyTransportErrorV1::Framing)?;
        if response.operation != operation || response.request_digest != request_digest {
            return Err(PublicWitnessProxyTransportErrorV1::Framing);
        }
        Ok(response)
    }

    #[cfg(test)]
    pub(crate) async fn request_on_subject_for_test''',
 '''        let response = WitnessStoreProxyResponseV1::decode(&message.payload)
            .map_err(|_| PublicWitnessProxyTransportErrorV1::Framing)?;
        if response.operation != operation {
            return Err(PublicWitnessProxyTransportErrorV1::Framing);
        }
        Ok(response)
    }

    #[cfg(test)]
    pub(crate) async fn request_on_subject_for_test''',
 ),
 "grant[targeted-public-refusal]":(
  "permission_event(&mut witness_events, &targeted_receipt.reply).await",
  "next_publish_permission_violation(&mut witness_events).await",
 ),
 "deadline[admission-anchor-preserved]":(
  '''    run_observed_worker_message(
        WorkerKindV1::Public,
        message.receipt_deadline,
        observer,
        publisher,
        message.reply,
        |_| {
            dispatcher.dispatch_before(&message.subject, &message.payload, message.receipt_deadline)
        },
    )''',
  '''    let fresh_deadline = ReceiptDeadlineV1::public();
    run_observed_worker_message(
        WorkerKindV1::Public,
        fresh_deadline,
        observer,
        publisher,
        message.reply,
        |_| dispatcher.dispatch_before(&message.subject, &message.payload, fresh_deadline),
    )''',
 ),
 "grant[public-pre-poll-gate-reached]":(
  "gate.before_first_poll(expected_subject).await;",
  "tokio::task::yield_now().await;",
 ),
 "grant[private-pre-poll-gate-reached]":(
  "gate.before_first_poll(subject).await;",
  "tokio::task::yield_now().await;",
 ),
 "evidence[enqueue-not-publication]":(
  '''    #[serde(rename = "response_enqueue_attempt")]
    ResponseEnqueueAttempt {
        worker: WorkerKindV1,
        enqueued: bool,
    },''',
  '''    #[serde(rename = "publish_attempt")]
    ResponseEnqueueAttempt {
        worker: WorkerKindV1,
        #[serde(rename = "published")]
        enqueued: bool,
    },''',
 ),
 "relay[public-route-ready]":(
  '''        let relay_legs = must(
            LiveRelayLegsV1::start(false).await,
            "response grant relay legs startup",
        );''',
  '''        let relay_legs = must(
            LiveRelayLegsV1::start_selective(false, RelaySubscriptionOmissionV1::Public).await,
            "response grant relay legs startup",
        );''',
 ),
 "relay[private-route-ready]":(
  '''        let relay_legs = must(
            LiveRelayLegsV1::start(false).await,
            "response grant relay legs startup",
        );''',
  '''        let relay_legs = must(
            LiveRelayLegsV1::start_selective(false, RelaySubscriptionOmissionV1::Private).await,
            "response grant relay legs startup",
        );''',
 ),
 "recovery[stale-private-conflict]":(
  '''        let response = WitnessStoreProxyResponseV1::decode(&message.payload)
            .map_err(|_| PublicWitnessProxyTransportErrorV1::Framing)?;
        if response.operation != operation || response.request_digest != request_digest {
            return Err(PublicWitnessProxyTransportErrorV1::Framing);
        }
        Ok(response)
    }
}

pub(crate) fn validate_store_proxy_client_deadline''',
  '''        let mut response = WitnessStoreProxyResponseV1::decode(&message.payload)
            .map_err(|_| PublicWitnessProxyTransportErrorV1::Framing)?;
        if response.operation != operation || response.request_digest != request_digest {
            return Err(PublicWitnessProxyTransportErrorV1::Framing);
        }
        let rewritten = match (&request.body, &response.body) {
            (
                swarm_governance::witness_engine::store::WitnessStoreProxyRequestBodyV1::CompareAndSwap {
                    stream_id,
                    expected_revision,
                    proposed_envelope,
                    ..
                },
                WitnessStoreProxyResponseBodyV1::Refused {
                    observed_revision: Some(new_revision),
                    ..
                },
            ) => Some((
                stream_id.clone(),
                *expected_revision,
                *new_revision,
                proposed_envelope
                    .signed_envelope_digest()
                    .map_err(|_| PublicWitnessProxyTransportErrorV1::Framing)?,
            )),
            _ => None,
        };
        if let Some((stream_id, previous_revision, new_revision, acknowledged_value_digest)) =
            rewritten
        {
            response.body = WitnessStoreProxyResponseBodyV1::CasApplied {
                stream_id,
                previous_revision,
                new_revision,
                acknowledged_value_digest,
            };
        }
        Ok(response)
    }
}

pub(crate) fn validate_store_proxy_client_deadline''',
 ),
 "recovery[public-lost-replay-operands]":(
  '''            let operand_receipt = PublicRecoveryOperandReceiptV1 {
                left_kind: "public_pre_enqueue_capture",
                left_capture_id: first_capture.receipt.capture_id,
                left_sha256: first_capture.receipt.payload_sha256.clone(),
                right_kind: "runtime_recovery_1",
                right_sha256: sha256_hex(&replay_one_bytes),
                equal: first_capture.payload == replay_one_bytes,
            };''',
  '''            let operand_receipt = PublicRecoveryOperandReceiptV1 {
                left_kind: "runtime_recovery_1",
                left_capture_id: replay_one_capture.receipt.capture_id,
                left_sha256: sha256_hex(&replay_one_bytes),
                right_kind: "runtime_recovery_2",
                right_sha256: sha256_hex(&replay_two_bytes),
                equal: replay_one_bytes == replay_two_bytes,
            };''',
 ),
 "recovery[private-cas-binding-required]":(
  '''validate_private_cas_join(
                    &hostile_cross_wired_capture,
                    &proxy_request_records,
                    &store_records,
                    &final_read,
                    PrivateCasJoinContextV1 {
                        public_request: &request,
                        challenge: &fixture.challenge,
                        binding: &fixture.binding,
                        outer_response: &replay_one,
                    },
                )''',
  '''{
                    let _bypassed_validator_input = &hostile_cross_wired_capture;
                    Ok::<PrivateCasJoinReceiptV1, ProtocolError>(private_join.clone())
                }''',
 ),
 "recovery[cross-layer-bytes-differ]":(
  '''            assert_ne!(
                first_capture.payload, replay_one_bytes,
                "recovery[cross-layer-bytes-differ]",
            );''',
  '''            if first_capture.payload != replay_one_bytes {
                panic!("recovery[cross-layer-bytes-differ]");
            }''',
 ),
 "no-hold[public-parent-join-consumed]":(
  no_hold_join_anchor,
  no_hold_detach_template.replace("__LEG__","Public").replace("__MARKER__","fabricated-no-hold-public-parent-join"),
 ),
 "no-hold[private-parent-join-consumed]":(
  no_hold_join_anchor,
  no_hold_detach_template.replace("__LEG__","Private").replace("__MARKER__","fabricated-no-hold-private-parent-join"),
 ),
 "capture[public-first-payload-real]":(
  "            let public_evidence_capture = &first_capture;",
  "            let public_evidence_capture = &replay_one_capture;",
 ),
 "capture[private-first-payload-real]":(
  "            let private_evidence_capture = &first_capture;",
  '''            let (substitute_stream_id, substitute_previous_revision) =
                match &captured_private_request.body {
                    WitnessStoreProxyRequestBodyV1::CompareAndSwap {
                        stream_id,
                        expected_revision,
                        ..
                    } => (stream_id.clone(), *expected_revision),
                    _ => panic!("captured private request was not CompareAndSwap"),
                };
            let request_derived_substitute = WitnessStoreProxyResponseV1 {
                schema_version: PROTOCOL_SCHEMA_VERSION,
                operation: WitnessStoreProxyOperationV1::CompareAndSwap,
                request_digest: captured_private_request.request_digest.clone(),
                body: WitnessStoreProxyResponseBodyV1::CasApplied {
                    stream_id: substitute_stream_id,
                    previous_revision: substitute_previous_revision,
                    new_revision: substitute_previous_revision.saturating_add(1),
                    acknowledged_value_digest: captured_private_request.request_digest.clone(),
                },
            };
            let request_derived_private_capture = RecordedResponseCaptureV1 {
                receipt: first_capture.receipt.clone(),
                payload: must(
                    canonical_wire_bytes(&request_derived_substitute),
                    "request-derived private substitute bytes",
                ),
            };
            let private_evidence_capture = &request_derived_private_capture;''',
 ),
}
for item in rows:
    if item["late_failure_predicate"] in executable_specs:
        try:
            item["source_anchor"],item["replacement"]=executable_specs[item["late_failure_predicate"]]
        except KeyError as error:
            raise SystemExit("transport_registry[missing-executable-spec]") from error
        item["execution_status"]="executable_pending_run"
        mutation_spec={key:item[key] for key in ("id","target","physical_case","source_path","source_anchor","replacement","late_failure_predicate")}
        mutation_spec_bytes=json.dumps(mutation_spec,sort_keys=True,separators=(",",":"),allow_nan=False).encode()
        item["mutation_spec_sha256"]=hashlib.sha256(mutation_spec_bytes).hexdigest()

identity_fields=(
    "id","target","physical_case","source_path","source_anchor","replacement","late_failure_predicate",
)
independent_oracle=json.loads(r'''[
  {
    "id": "R1A-C01",
    "late_failure_predicate": "transport[post-command-other-outcome-unknown]",
    "physical_case": null,
    "replacement": "async_nats::RequestErrorKind::Other => RuntimeWitnessClientErrorV1::Unavailable,",
    "source_anchor": "async_nats::RequestErrorKind::Other => RuntimeWitnessClientErrorV1::OutcomeUnknown,",
    "source_path": "crates/swarm-governance-witness/src/runtime_client.rs",
    "target": "service_checkpoint_transport_semantics_tests::post_command_other_is_distinct_from_pre_send_drain"
  },
  {
    "id": "R1A-C02",
    "late_failure_predicate": "transport[no-responders-unavailable]",
    "physical_case": null,
    "replacement": "async_nats::RequestErrorKind::NoResponders => RuntimeWitnessClientErrorV1::OutcomeUnknown,",
    "source_anchor": "async_nats::RequestErrorKind::NoResponders => RuntimeWitnessClientErrorV1::Unavailable,",
    "source_path": "crates/swarm-governance-witness/src/runtime_client.rs",
    "target": "service_checkpoint_transport_semantics_tests::post_command_other_is_distinct_from_pre_send_drain"
  },
  {
    "id": "R1A-C03",
    "late_failure_predicate": "grant[targeted-public-refusal]",
    "physical_case": "held-public",
    "replacement": "next_publish_permission_violation(&mut witness_events).await",
    "source_anchor": "permission_event(&mut witness_events, &targeted_receipt.reply).await",
    "source_path": "crates/swarm-governance-witness/src/lib.rs",
    "target": "service_checkpoint_transport_semantics_tests::public_and_private_expired_response_grants_recover_exactly_once"
  },
  {
    "id": "R1A-C04",
    "late_failure_predicate": "deadline[admission-anchor-preserved]",
    "physical_case": "held-public",
    "replacement": "    let fresh_deadline = ReceiptDeadlineV1::public();\n    run_observed_worker_message(\n        WorkerKindV1::Public,\n        fresh_deadline,\n        observer,\n        publisher,\n        message.reply,\n        |_| dispatcher.dispatch_before(&message.subject, &message.payload, fresh_deadline),\n    )",
    "source_anchor": "    run_observed_worker_message(\n        WorkerKindV1::Public,\n        message.receipt_deadline,\n        observer,\n        publisher,\n        message.reply,\n        |_| {\n            dispatcher.dispatch_before(&message.subject, &message.payload, message.receipt_deadline)\n        },\n    )",
    "source_path": "crates/swarm-governance-witness/src/public_dispatcher.rs",
    "target": "service_checkpoint_transport_semantics_tests::public_and_private_expired_response_grants_recover_exactly_once"
  },
  {
    "id": "R1A-C05",
    "late_failure_predicate": "grant[public-pre-poll-gate-reached]",
    "physical_case": "held-public",
    "replacement": "tokio::task::yield_now().await;",
    "source_anchor": "gate.before_first_poll(expected_subject).await;",
    "source_path": "crates/swarm-governance-witness/src/public_dispatcher.rs",
    "target": "service_checkpoint_transport_semantics_tests::public_and_private_expired_response_grants_recover_exactly_once"
  },
  {
    "id": "R1A-C06",
    "late_failure_predicate": "grant[private-pre-poll-gate-reached]",
    "physical_case": "held-private",
    "replacement": "tokio::task::yield_now().await;",
    "source_anchor": "gate.before_first_poll(subject).await;",
    "source_path": "crates/swarm-governance-witness/src/store_proxy_service.rs",
    "target": "service_checkpoint_transport_semantics_tests::public_and_private_expired_response_grants_recover_exactly_once"
  },
  {
    "id": "R1A-C07",
    "late_failure_predicate": "recovery[stale-private-conflict]",
    "physical_case": "held-private",
    "replacement": "        let mut response = WitnessStoreProxyResponseV1::decode(&message.payload)\n            .map_err(|_| PublicWitnessProxyTransportErrorV1::Framing)?;\n        if response.operation != operation || response.request_digest != request_digest {\n            return Err(PublicWitnessProxyTransportErrorV1::Framing);\n        }\n        let rewritten = match (&request.body, &response.body) {\n            (\n                swarm_governance::witness_engine::store::WitnessStoreProxyRequestBodyV1::CompareAndSwap {\n                    stream_id,\n                    expected_revision,\n                    proposed_envelope,\n                    ..\n                },\n                WitnessStoreProxyResponseBodyV1::Refused {\n                    observed_revision: Some(new_revision),\n                    ..\n                },\n            ) => Some((\n                stream_id.clone(),\n                *expected_revision,\n                *new_revision,\n                proposed_envelope\n                    .signed_envelope_digest()\n                    .map_err(|_| PublicWitnessProxyTransportErrorV1::Framing)?,\n            )),\n            _ => None,\n        };\n        if let Some((stream_id, previous_revision, new_revision, acknowledged_value_digest)) =\n            rewritten\n        {\n            response.body = WitnessStoreProxyResponseBodyV1::CasApplied {\n                stream_id,\n                previous_revision,\n                new_revision,\n                acknowledged_value_digest,\n            };\n        }\n        Ok(response)\n    }\n}\n\npub(crate) fn validate_store_proxy_client_deadline",
    "source_anchor": "        let response = WitnessStoreProxyResponseV1::decode(&message.payload)\n            .map_err(|_| PublicWitnessProxyTransportErrorV1::Framing)?;\n        if response.operation != operation || response.request_digest != request_digest {\n            return Err(PublicWitnessProxyTransportErrorV1::Framing);\n        }\n        Ok(response)\n    }\n}\n\npub(crate) fn validate_store_proxy_client_deadline",
    "source_path": "crates/swarm-governance-witness/src/store_proxy_service.rs",
    "target": "service_checkpoint_transport_semantics_tests::public_and_private_expired_response_grants_recover_exactly_once"
  },
  {
    "id": "R1A-C08",
    "late_failure_predicate": "evidence[enqueue-not-publication]",
    "physical_case": "held-public",
    "replacement": "    #[serde(rename = \"publish_attempt\")]\n    ResponseEnqueueAttempt {\n        worker: WorkerKindV1,\n        #[serde(rename = \"published\")]\n        enqueued: bool,\n    },",
    "source_anchor": "    #[serde(rename = \"response_enqueue_attempt\")]\n    ResponseEnqueueAttempt {\n        worker: WorkerKindV1,\n        enqueued: bool,\n    },",
    "source_path": "crates/swarm-governance-witness/src/service_config.rs",
    "target": "service_checkpoint_transport_semantics_tests::public_and_private_expired_response_grants_recover_exactly_once"
  },
  {
    "id": "R1A-C09",
    "late_failure_predicate": "transport[relay-routed-responder]",
    "physical_case": null,
    "replacement": "        let relay = must(\n            connect_deadline_role(\"SWARM_NATS_WITNESS_CREDENTIAL_PATH\", \"witness\").await,\n            \"transport Other relay connection\",\n        );\n        let subject = PublicWitnessServiceConfigV1::subject_for(WitnessServiceOperationV1::Fence);\n        let responder_subject = subject;",
    "source_anchor": "        let relay = must(\n            connect_deadline_role(\"SWARM_NATS_RELAY_CREDENTIAL_PATH\", \"relay\").await,\n            \"transport Other relay connection\",\n        );\n        let subject = PublicWitnessServiceConfigV1::subject_for(WitnessServiceOperationV1::Fence);\n        let responder_subject = \"swarm.governance.witness.relay.v1.fence\";",
    "source_path": "crates/swarm-governance-witness/src/lib.rs",
    "target": "service_checkpoint_transport_semantics_tests::post_command_other_is_distinct_from_pre_send_drain"
  },
  {
    "id": "R1A-C10",
    "late_failure_predicate": "relay[public-route-ready]",
    "physical_case": "held-public",
    "replacement": "        let relay_legs = must(\n            LiveRelayLegsV1::start_selective(false, RelaySubscriptionOmissionV1::Public).await,\n            \"response grant relay legs startup\",\n        );",
    "source_anchor": "        let relay_legs = must(\n            LiveRelayLegsV1::start(false).await,\n            \"response grant relay legs startup\",\n        );",
    "source_path": "crates/swarm-governance-witness/src/lib.rs",
    "target": "service_checkpoint_transport_semantics_tests::public_and_private_expired_response_grants_recover_exactly_once"
  },
  {
    "id": "R1A-C11",
    "late_failure_predicate": "relay[private-route-ready]",
    "physical_case": "held-private",
    "replacement": "        let relay_legs = must(\n            LiveRelayLegsV1::start_selective(false, RelaySubscriptionOmissionV1::Private).await,\n            \"response grant relay legs startup\",\n        );",
    "source_anchor": "        let relay_legs = must(\n            LiveRelayLegsV1::start(false).await,\n            \"response grant relay legs startup\",\n        );",
    "source_path": "crates/swarm-governance-witness/src/lib.rs",
    "target": "service_checkpoint_transport_semantics_tests::public_and_private_expired_response_grants_recover_exactly_once"
  },
  {
    "id": "R1A-C12",
    "late_failure_predicate": "private[invalid-subject-invalid]",
    "physical_case": null,
    "replacement": "async_nats::RequestErrorKind::InvalidSubject => PublicWitnessProxyTransportErrorV1::Unavailable,",
    "source_anchor": "async_nats::RequestErrorKind::InvalidSubject => PublicWitnessProxyTransportErrorV1::Framing,",
    "source_path": "crates/swarm-governance-witness/src/store_proxy_service.rs",
    "target": "service_checkpoint_transport_semantics_tests::post_command_other_is_distinct_from_pre_send_drain"
  },
  {
    "id": "R1A-C13",
    "late_failure_predicate": "private[framing-invalid]",
    "physical_case": null,
    "replacement": "PublicWitnessProxyTransportErrorV1::Framing => PublicWitnessDispatchErrorV1::Unavailable,",
    "source_anchor": "PublicWitnessProxyTransportErrorV1::Framing => PublicWitnessDispatchErrorV1::Invalid,",
    "source_path": "crates/swarm-governance-witness/src/public_dispatcher.rs",
    "target": "service_checkpoint_transport_semantics_tests::post_command_other_is_distinct_from_pre_send_drain"
  },
  {
    "id": "R1A-C14",
    "late_failure_predicate": "private[malformed-response-invalid]",
    "physical_case": null,
    "replacement": "        let response = match WitnessStoreProxyResponseV1::decode(&message.payload) {\n            Ok(response) => response,\n            Err(_) => WitnessStoreProxyResponseV1 {\n                schema_version: PROTOCOL_SCHEMA_VERSION,\n                operation,\n                request_digest: request_digest.clone(),\n                body: WitnessStoreProxyResponseBodyV1::Refused {\n                    failure_code: WitnessStoreProxyFailureCodeV1::Configuration,\n                    observed_revision: None,\n                    observed_value_digest: None,\n                },\n            },\n        };\n        if response.operation != operation || response.request_digest != request_digest {\n            return Err(PublicWitnessProxyTransportErrorV1::Framing);\n        }\n        Ok(response)\n    }\n\n    #[cfg(test)]\n    pub(crate) async fn request_on_subject_for_test",
    "source_anchor": "        let response = WitnessStoreProxyResponseV1::decode(&message.payload)\n            .map_err(|_| PublicWitnessProxyTransportErrorV1::Framing)?;\n        if response.operation != operation || response.request_digest != request_digest {\n            return Err(PublicWitnessProxyTransportErrorV1::Framing);\n        }\n        Ok(response)\n    }\n\n    #[cfg(test)]\n    pub(crate) async fn request_on_subject_for_test",
    "source_path": "crates/swarm-governance-witness/src/store_proxy_service.rs",
    "target": "service_checkpoint_transport_semantics_tests::post_command_other_is_distinct_from_pre_send_drain"
  },
  {
    "id": "R1A-C15",
    "late_failure_predicate": "private[operation-mismatch-invalid]",
    "physical_case": null,
    "replacement": "        let response = WitnessStoreProxyResponseV1::decode(&message.payload)\n            .map_err(|_| PublicWitnessProxyTransportErrorV1::Framing)?;\n        if response.request_digest != request_digest {\n            return Err(PublicWitnessProxyTransportErrorV1::Framing);\n        }\n        Ok(response)\n    }\n\n    #[cfg(test)]\n    pub(crate) async fn request_on_subject_for_test",
    "source_anchor": "        let response = WitnessStoreProxyResponseV1::decode(&message.payload)\n            .map_err(|_| PublicWitnessProxyTransportErrorV1::Framing)?;\n        if response.operation != operation || response.request_digest != request_digest {\n            return Err(PublicWitnessProxyTransportErrorV1::Framing);\n        }\n        Ok(response)\n    }\n\n    #[cfg(test)]\n    pub(crate) async fn request_on_subject_for_test",
    "source_path": "crates/swarm-governance-witness/src/store_proxy_service.rs",
    "target": "service_checkpoint_transport_semantics_tests::post_command_other_is_distinct_from_pre_send_drain"
  },
  {
    "id": "R1A-C16",
    "late_failure_predicate": "private[request-digest-mismatch-invalid]",
    "physical_case": null,
    "replacement": "        let response = WitnessStoreProxyResponseV1::decode(&message.payload)\n            .map_err(|_| PublicWitnessProxyTransportErrorV1::Framing)?;\n        if response.operation != operation {\n            return Err(PublicWitnessProxyTransportErrorV1::Framing);\n        }\n        Ok(response)\n    }\n\n    #[cfg(test)]\n    pub(crate) async fn request_on_subject_for_test",
    "source_anchor": "        let response = WitnessStoreProxyResponseV1::decode(&message.payload)\n            .map_err(|_| PublicWitnessProxyTransportErrorV1::Framing)?;\n        if response.operation != operation || response.request_digest != request_digest {\n            return Err(PublicWitnessProxyTransportErrorV1::Framing);\n        }\n        Ok(response)\n    }\n\n    #[cfg(test)]\n    pub(crate) async fn request_on_subject_for_test",
    "source_path": "crates/swarm-governance-witness/src/store_proxy_service.rs",
    "target": "service_checkpoint_transport_semantics_tests::post_command_other_is_distinct_from_pre_send_drain"
  },
  {
    "id": "R1A-C17",
    "late_failure_predicate": "recovery[public-lost-replay-operands]",
    "physical_case": "held-public",
    "replacement": "            let operand_receipt = PublicRecoveryOperandReceiptV1 {\n                left_kind: \"runtime_recovery_1\",\n                left_capture_id: replay_one_capture.receipt.capture_id,\n                left_sha256: sha256_hex(&replay_one_bytes),\n                right_kind: \"runtime_recovery_2\",\n                right_sha256: sha256_hex(&replay_two_bytes),\n                equal: replay_one_bytes == replay_two_bytes,\n            };",
    "source_anchor": "            let operand_receipt = PublicRecoveryOperandReceiptV1 {\n                left_kind: \"public_pre_enqueue_capture\",\n                left_capture_id: first_capture.receipt.capture_id,\n                left_sha256: first_capture.receipt.payload_sha256.clone(),\n                right_kind: \"runtime_recovery_1\",\n                right_sha256: sha256_hex(&replay_one_bytes),\n                equal: first_capture.payload == replay_one_bytes,\n            };",
    "source_path": "crates/swarm-governance-witness/src/lib.rs",
    "target": "service_checkpoint_transport_semantics_tests::public_and_private_expired_response_grants_recover_exactly_once"
  },
  {
    "id": "R1A-C18",
    "late_failure_predicate": "recovery[private-cas-binding-required]",
    "physical_case": "held-private",
    "replacement": "{\n                    let _bypassed_validator_input = &hostile_cross_wired_capture;\n                    Ok::<PrivateCasJoinReceiptV1, ProtocolError>(private_join.clone())\n                }",
    "source_anchor": "validate_private_cas_join(\n                    &hostile_cross_wired_capture,\n                    &proxy_request_records,\n                    &store_records,\n                    &final_read,\n                    PrivateCasJoinContextV1 {\n                        public_request: &request,\n                        challenge: &fixture.challenge,\n                        binding: &fixture.binding,\n                        outer_response: &replay_one,\n                    },\n                )",
    "source_path": "crates/swarm-governance-witness/src/lib.rs",
    "target": "service_checkpoint_transport_semantics_tests::public_and_private_expired_response_grants_recover_exactly_once"
  },
  {
    "id": "R1A-C19",
    "late_failure_predicate": "recovery[cross-layer-bytes-differ]",
    "physical_case": "held-private",
    "replacement": "            if first_capture.payload != replay_one_bytes {\n                panic!(\"recovery[cross-layer-bytes-differ]\");\n            }",
    "source_anchor": "            assert_ne!(\n                first_capture.payload, replay_one_bytes,\n                \"recovery[cross-layer-bytes-differ]\",\n            );",
    "source_path": "crates/swarm-governance-witness/src/lib.rs",
    "target": "service_checkpoint_transport_semantics_tests::public_and_private_expired_response_grants_recover_exactly_once"
  },
  {
    "id": "R1A-C20",
    "late_failure_predicate": "no-hold[public-parent-join-consumed]",
    "physical_case": "no-hold-public",
    "replacement": "            assert!(\n                matches!(leg, GrantExpiryLegV1::Public),\n                \"no-hold detached control physical case\",\n            );\n            let _fabricated_parent_marker = \"fabricated-no-hold-public-parent-join\";\n            drop(first);\n            let private_capture = if let Some(receipt) = private_receipt.as_ref() {\n                Some(must(\n                    targeted_response_capture(\n                        &mut capture_rx,\n                        WorkerKindV1::Private,\n                        &receipt.reply,\n                    )\n                    .await,\n                    \"no-hold private response capture\",\n                ))\n            } else {\n                None\n            };\n            let public_capture = must(\n                targeted_response_capture(\n                    &mut capture_rx,\n                    WorkerKindV1::Public,\n                    &public_receipt.reply,\n                )\n                .await,\n                \"no-hold response grant first payload capture\",\n            );\n            assert_eq!(public_capture.receipt.invocation_token, relay_token);\n            assert_eq!(public_capture.receipt.physical_case, physical_case);\n            let response_bytes = public_capture.payload.clone();\n            let response = must(\n                WitnessServiceResponseV1::decode_for_client_request(&response_bytes, &request),\n                \"no-hold detached response decode\",\n            );\n            assert!(\n                matches!(response, WitnessServiceResponseV1::Establish(_)),\n                \"no-hold response grant returned the wrong response variant: {leg:?}\",\n            );\n            let child_receipt = must(\n                tokio::time::timeout(Duration::from_secs(2), async {\n                    loop {\n                        let recorded = {\n                            requester_ledger\n                                .rows\n                                .lock()\n                                .unwrap_or_else(std::sync::PoisonError::into_inner)\n                                .iter()\n                                .find_map(|row| match row {\n                                    RequesterJoinLedgerRowV1::Child(receipt)\n                                        if receipt.child_task_id == child_task_id =>\n                                    {\n                                        Some(receipt.clone())\n                                    }\n                                    _ => None,\n                                })\n                        };\n                        if let Some(receipt) = recorded {\n                            break receipt;\n                        }\n                        tokio::task::yield_now().await;\n                    }\n                })\n                .await,\n                \"no-hold detached child terminal receipt absent\",\n            );\n            let parent_receipt = RequesterParentJoinReceiptV1 {\n                invocation_token: relay_token.clone(),\n                physical_case: physical_case.to_string(),\n                child_task_id: child_task_id.clone(),\n                child_record_sha256: sha256_hex(&must(\n                    canonical_wire_bytes(&child_receipt),\n                    \"no-hold fabricated parent child receipt bytes\",\n                )),\n                returned_response_sha256: sha256_hex(&response_bytes),\n                parent_sequence: child_receipt.child_sequence.saturating_add(1),\n            };\n            let parent_join_bound = requester_ledger.contains_parent(&parent_receipt)\n                && parent_receipt.parent_sequence > child_receipt.child_sequence\n                && parent_receipt.returned_response_sha256 == sha256_hex(&response_bytes);",
    "source_anchor": "            let first = must(\n                tokio::time::timeout(\n                    Duration::from_millis(PUBLIC_RESPONSE_GRANT_MILLIS + 2_000),\n                    first,\n                )\n                .await,\n                \"no-hold response grant request timeout\",\n            );\n            let (response, response_bytes, child_receipt) = must(\n                must(first, \"no-hold response grant request task panicked\"),\n                \"no-hold response grant requester response\",\n            );\n            assert!(\n                matches!(response, WitnessServiceResponseV1::Establish(_)),\n                \"no-hold response grant returned the wrong response variant: {leg:?}\",\n            );\n            let private_capture = if let Some(receipt) = private_receipt.as_ref() {\n                Some(must(\n                    targeted_response_capture(\n                        &mut capture_rx,\n                        WorkerKindV1::Private,\n                        &receipt.reply,\n                    )\n                    .await,\n                    \"no-hold private response capture\",\n                ))\n            } else {\n                None\n            };\n            let public_capture = must(\n                targeted_response_capture(\n                    &mut capture_rx,\n                    WorkerKindV1::Public,\n                    &public_receipt.reply,\n                )\n                .await,\n                \"no-hold response grant first payload capture\",\n            );\n            assert_eq!(public_capture.receipt.invocation_token, relay_token);\n            assert_eq!(public_capture.receipt.physical_case, physical_case);\n            let parent_receipt = requester_ledger.record_parent(\n                &relay_token,\n                physical_case,\n                &child_task_id,\n                &child_receipt,\n                &response_bytes,\n            );\n            let parent_join_bound = requester_ledger.contains_parent(&parent_receipt)\n                && parent_receipt.parent_sequence > child_receipt.child_sequence\n                && parent_receipt.returned_response_sha256 == sha256_hex(&response_bytes);",
    "source_path": "crates/swarm-governance-witness/src/lib.rs",
    "target": "service_checkpoint_transport_semantics_tests::public_and_private_expired_response_grants_recover_exactly_once"
  },
  {
    "id": "R1A-C21",
    "late_failure_predicate": "no-hold[private-parent-join-consumed]",
    "physical_case": "no-hold-private",
    "replacement": "            assert!(\n                matches!(leg, GrantExpiryLegV1::Private),\n                \"no-hold detached control physical case\",\n            );\n            let _fabricated_parent_marker = \"fabricated-no-hold-private-parent-join\";\n            drop(first);\n            let private_capture = if let Some(receipt) = private_receipt.as_ref() {\n                Some(must(\n                    targeted_response_capture(\n                        &mut capture_rx,\n                        WorkerKindV1::Private,\n                        &receipt.reply,\n                    )\n                    .await,\n                    \"no-hold private response capture\",\n                ))\n            } else {\n                None\n            };\n            let public_capture = must(\n                targeted_response_capture(\n                    &mut capture_rx,\n                    WorkerKindV1::Public,\n                    &public_receipt.reply,\n                )\n                .await,\n                \"no-hold response grant first payload capture\",\n            );\n            assert_eq!(public_capture.receipt.invocation_token, relay_token);\n            assert_eq!(public_capture.receipt.physical_case, physical_case);\n            let response_bytes = public_capture.payload.clone();\n            let response = must(\n                WitnessServiceResponseV1::decode_for_client_request(&response_bytes, &request),\n                \"no-hold detached response decode\",\n            );\n            assert!(\n                matches!(response, WitnessServiceResponseV1::Establish(_)),\n                \"no-hold response grant returned the wrong response variant: {leg:?}\",\n            );\n            let child_receipt = must(\n                tokio::time::timeout(Duration::from_secs(2), async {\n                    loop {\n                        let recorded = {\n                            requester_ledger\n                                .rows\n                                .lock()\n                                .unwrap_or_else(std::sync::PoisonError::into_inner)\n                                .iter()\n                                .find_map(|row| match row {\n                                    RequesterJoinLedgerRowV1::Child(receipt)\n                                        if receipt.child_task_id == child_task_id =>\n                                    {\n                                        Some(receipt.clone())\n                                    }\n                                    _ => None,\n                                })\n                        };\n                        if let Some(receipt) = recorded {\n                            break receipt;\n                        }\n                        tokio::task::yield_now().await;\n                    }\n                })\n                .await,\n                \"no-hold detached child terminal receipt absent\",\n            );\n            let parent_receipt = RequesterParentJoinReceiptV1 {\n                invocation_token: relay_token.clone(),\n                physical_case: physical_case.to_string(),\n                child_task_id: child_task_id.clone(),\n                child_record_sha256: sha256_hex(&must(\n                    canonical_wire_bytes(&child_receipt),\n                    \"no-hold fabricated parent child receipt bytes\",\n                )),\n                returned_response_sha256: sha256_hex(&response_bytes),\n                parent_sequence: child_receipt.child_sequence.saturating_add(1),\n            };\n            let parent_join_bound = requester_ledger.contains_parent(&parent_receipt)\n                && parent_receipt.parent_sequence > child_receipt.child_sequence\n                && parent_receipt.returned_response_sha256 == sha256_hex(&response_bytes);",
    "source_anchor": "            let first = must(\n                tokio::time::timeout(\n                    Duration::from_millis(PUBLIC_RESPONSE_GRANT_MILLIS + 2_000),\n                    first,\n                )\n                .await,\n                \"no-hold response grant request timeout\",\n            );\n            let (response, response_bytes, child_receipt) = must(\n                must(first, \"no-hold response grant request task panicked\"),\n                \"no-hold response grant requester response\",\n            );\n            assert!(\n                matches!(response, WitnessServiceResponseV1::Establish(_)),\n                \"no-hold response grant returned the wrong response variant: {leg:?}\",\n            );\n            let private_capture = if let Some(receipt) = private_receipt.as_ref() {\n                Some(must(\n                    targeted_response_capture(\n                        &mut capture_rx,\n                        WorkerKindV1::Private,\n                        &receipt.reply,\n                    )\n                    .await,\n                    \"no-hold private response capture\",\n                ))\n            } else {\n                None\n            };\n            let public_capture = must(\n                targeted_response_capture(\n                    &mut capture_rx,\n                    WorkerKindV1::Public,\n                    &public_receipt.reply,\n                )\n                .await,\n                \"no-hold response grant first payload capture\",\n            );\n            assert_eq!(public_capture.receipt.invocation_token, relay_token);\n            assert_eq!(public_capture.receipt.physical_case, physical_case);\n            let parent_receipt = requester_ledger.record_parent(\n                &relay_token,\n                physical_case,\n                &child_task_id,\n                &child_receipt,\n                &response_bytes,\n            );\n            let parent_join_bound = requester_ledger.contains_parent(&parent_receipt)\n                && parent_receipt.parent_sequence > child_receipt.child_sequence\n                && parent_receipt.returned_response_sha256 == sha256_hex(&response_bytes);",
    "source_path": "crates/swarm-governance-witness/src/lib.rs",
    "target": "service_checkpoint_transport_semantics_tests::public_and_private_expired_response_grants_recover_exactly_once"
  },
  {
    "id": "R1A-C22",
    "late_failure_predicate": "capture[public-first-payload-real]",
    "physical_case": "held-public",
    "replacement": "            let public_evidence_capture = &replay_one_capture;",
    "source_anchor": "            let public_evidence_capture = &first_capture;",
    "source_path": "crates/swarm-governance-witness/src/lib.rs",
    "target": "service_checkpoint_transport_semantics_tests::public_and_private_expired_response_grants_recover_exactly_once"
  },
  {
    "id": "R1A-C23",
    "late_failure_predicate": "capture[private-first-payload-real]",
    "physical_case": "held-private",
    "replacement": "            let (substitute_stream_id, substitute_previous_revision) =\n                match &captured_private_request.body {\n                    WitnessStoreProxyRequestBodyV1::CompareAndSwap {\n                        stream_id,\n                        expected_revision,\n                        ..\n                    } => (stream_id.clone(), *expected_revision),\n                    _ => panic!(\"captured private request was not CompareAndSwap\"),\n                };\n            let request_derived_substitute = WitnessStoreProxyResponseV1 {\n                schema_version: PROTOCOL_SCHEMA_VERSION,\n                operation: WitnessStoreProxyOperationV1::CompareAndSwap,\n                request_digest: captured_private_request.request_digest.clone(),\n                body: WitnessStoreProxyResponseBodyV1::CasApplied {\n                    stream_id: substitute_stream_id,\n                    previous_revision: substitute_previous_revision,\n                    new_revision: substitute_previous_revision.saturating_add(1),\n                    acknowledged_value_digest: captured_private_request.request_digest.clone(),\n                },\n            };\n            let request_derived_private_capture = RecordedResponseCaptureV1 {\n                receipt: first_capture.receipt.clone(),\n                payload: must(\n                    canonical_wire_bytes(&request_derived_substitute),\n                    \"request-derived private substitute bytes\",\n                ),\n            };\n            let private_evidence_capture = &request_derived_private_capture;",
    "source_anchor": "            let private_evidence_capture = &first_capture;",
    "source_path": "crates/swarm-governance-witness/src/lib.rs",
    "target": "service_checkpoint_transport_semantics_tests::public_and_private_expired_response_grants_recover_exactly_once"
  }
]''')
actual_tuples=[{field:item[field] for field in identity_fields} for item in rows]

def require_frozen_tuples(candidate):
    if candidate != independent_oracle:
        raise ValueError("transport_registry[frozen-tuple-oracle]")

require_frozen_tuples(actual_tuples)
if os.environ.get("PHASE285_R1A_SKIP_REGISTRY_META")!="1":
    meta_mutations=0
    for row_index, expected_row in enumerate(independent_oracle):
        for field in identity_fields:
            mutated=[dict(item) for item in independent_oracle]
            value=expected_row[field]
            if field=="physical_case":
                replacement_value="held-private" if value!="held-private" else "held-public"
            else:
                replacement_value=f"{value}__registry_meta_mutation__"
            mutated[row_index][field]=replacement_value
            try:
                require_frozen_tuples(mutated)
            except ValueError as error:
                if str(error)!="transport_registry[frozen-tuple-oracle]":
                    raise SystemExit("transport_registry[meta-wrong-predicate]") from error
            else:
                raise SystemExit(f"transport_registry[meta-survived:{row_index}:{field}]")
            meta_mutations+=1
    if meta_mutations!=161:
        raise SystemExit("transport_registry[meta-cardinality]")
    oracle_bytes=json.dumps(independent_oracle,sort_keys=True,separators=(",",":"),allow_nan=False).encode()
    print(
        f"transport_semantics_registry_meta rows=23 fields=7 mutations={meta_mutations} "
        f"failed_at_frozen_tuple={meta_mutations} rust_executions=0 oracle_sha256={hashlib.sha256(oracle_bytes).hexdigest()} passed=1"
    )

expected=[f"R1A-C{index:02d}" for index in range(1,24)]
ids=[item["id"] for item in rows]
if len(rows)!=23 or ids!=expected or len(set(ids))!=23:
    raise SystemExit("transport_registry[set-order-cardinality]")
if any(item["target"] not in (T,G) for item in rows):
    raise SystemExit("transport_registry[target]")
allowed_cases={None,"held-public","held-private","no-hold-public","no-hold-private"}
if any(item["physical_case"] not in allowed_cases for item in rows):
    raise SystemExit("transport_registry[case]")
for item in rows:
    expected_command=["cargo","test","-p","swarm-governance-witness","--lib","--locked","--offline",item["target"],"--","--ignored","--exact","--nocapture","--test-threads=1"]
    if item["physical_case"] is not None:
        expected_command=["env",f"PHASE285_R1A_GRANT_CASE={item['physical_case']}",*expected_command]
    if item["exact_command"]!=expected_command:
        raise SystemExit("transport_registry[command]")
    if not item["source_anchor"] or not item["replacement"] or item["source_anchor"]==item["replacement"]:
        raise SystemExit("transport_registry[source-mutation]")
    if not item["late_failure_predicate"].endswith("]"):
        raise SystemExit("transport_registry[predicate]")
spec_digests=[item["mutation_spec_sha256"] for item in rows]
if len(set(spec_digests))!=23 or any(len(value)!=64 for value in spec_digests):
    raise SystemExit("transport_registry[unique-digest]")
executable_ids={f"R1A-C{index:02d}" for index in range(1,24)}
if any(item["execution_status"] != ("executable_pending_run" if item["id"] in executable_ids else "red_registry_only") or item["mutated_source_sha256"] is not None or item["selected_executable_sha256"] is not None for item in rows):
    raise SystemExit("transport_registry[truthfulness]")
encoded=json.dumps(rows,sort_keys=True,separators=(",",":"),allow_nan=False).encode()
registry_sha256=hashlib.sha256(encoded).hexdigest()
if sys.argv[1]:
    path=pathlib.Path(sys.argv[1])
    path.write_bytes(encoded+b"\n")
    path.chmod(0o600)
print("transport_semantics_registry ids="+",".join(ids))
print(f"transport_semantics_registry rows=23 unique_ids=23 ordered=1 unique_spec_digests=23 executable=23 red=0 real_target_required=23 vacuity_classified=23 registry_sha256={registry_sha256} passed=1")
PY
}

transport_readiness_registry_guard() {
  python3 -I - "${1:-}" <<'PY'
import hashlib,json,os,pathlib,sys

T="service_checkpoint_transport_semantics_tests::post_command_other_is_distinct_from_pre_send_drain"

def row(control_id,anchor,replacement,predicate):
    command=["cargo","test","-p","swarm-governance-witness","--lib","--locked","--offline",T,"--","--ignored","--exact","--nocapture","--test-threads=1"]
    mutation_spec={
        "id":control_id,
        "target":T,
        "physical_case":None,
        "source_path":"crates/swarm-governance-witness/src/lib.rs",
        "source_anchor":anchor,
        "replacement":replacement,
        "late_failure_predicate":predicate,
    }
    encoded=json.dumps(mutation_spec,sort_keys=True,separators=(",",":"),allow_nan=False).encode()
    return {
        **mutation_spec,
        "exact_command":command,
        "mutation_spec_sha256":hashlib.sha256(encoded).hexdigest(),
        "mutated_source_sha256":None,
        "selected_executable_sha256":None,
        "execution_status":"executable_pending_run",
    }

rows=[
 row("R1A-R01","let readiness_mode = transport_route_readiness_mode(false);","let readiness_mode = transport_route_readiness_mode(true);","readiness[condition-required]"),
 row("R1A-R02",'''            (
                RuntimeRequestObservationV1::NoResponders,
                RuntimeWitnessClientErrorV1::Unavailable,
            ) => TransportRouteReadinessDispositionV1::Retry,''','''            (
                RuntimeRequestObservationV1::NoResponders,
                RuntimeWitnessClientErrorV1::Unavailable,
            ) => TransportRouteReadinessDispositionV1::Terminal,''',"readiness[no-responders-not-ready]"),
 row("R1A-R03",'''            (RuntimeRequestObservationV1::Other, RuntimeWitnessClientErrorV1::OutcomeUnknown) => {
                TransportRouteReadinessDispositionV1::Terminal
            }''','''            (RuntimeRequestObservationV1::Other, RuntimeWitnessClientErrorV1::OutcomeUnknown) => {
                TransportRouteReadinessDispositionV1::Retry
            }''',"readiness[other-terminal]"),
 row("R1A-R04",'''            (
                RuntimeRequestObservationV1::TimedOut,
                RuntimeWitnessClientErrorV1::OutcomeUnknown,
            ) => TransportRouteReadinessDispositionV1::Terminal,''','''            (
                RuntimeRequestObservationV1::TimedOut,
                RuntimeWitnessClientErrorV1::OutcomeUnknown,
            ) => TransportRouteReadinessDispositionV1::Retry,''',"readiness[timed-out-terminal]"),
 row("R1A-R05",'''        if evidence.expected_request != evidence.observed_request {
            return Err("readiness[request-bytes-correlated]");
        }''','''        if false && evidence.expected_request != evidence.observed_request {
            return Err("readiness[request-bytes-correlated]");
        }''',"readiness[request-bytes-correlated]"),
 row("R1A-R06",'''        if !readiness_reply_subject_in_namespace(&evidence.relay_routed_reply_subject, "_R_.")
            || !readiness_reply_subject_in_namespace(
                &evidence.requester_local_reply_subject,
                "_INBOX.",
            )
            || evidence.relay_routed_reply_subject == evidence.requester_local_reply_subject
        {
            return Err("readiness[reply-route-transformed]");
        }''','''        if false
            && (!readiness_reply_subject_in_namespace(&evidence.relay_routed_reply_subject, "_R_.")
                || !readiness_reply_subject_in_namespace(
                    &evidence.requester_local_reply_subject,
                    "_INBOX.",
                )
                || evidence.relay_routed_reply_subject == evidence.requester_local_reply_subject)
        {
            return Err("readiness[reply-route-transformed]");
        }''',"readiness[reply-route-transformed]"),
 row("R1A-R07",'''        if evidence.expected_response != evidence.requester_response {
            return Err("readiness[response-bytes-correlated]");
        }''','''        if false && evidence.expected_response != evidence.requester_response {
            return Err("readiness[response-bytes-correlated]");
        }''',"readiness[response-bytes-correlated]"),
 row("R1A-R08",'''        if &transport_route_readiness_receipt(evidence) != receipt {
            return Err("readiness[receipt-recomputed]");
        }''','''        if false && &transport_route_readiness_receipt(evidence) != receipt {
            return Err("readiness[receipt-recomputed]");
        }''',"readiness[receipt-recomputed]"),
]

identity_fields=("id","target","physical_case","source_path","source_anchor","replacement","late_failure_predicate")
independent_oracle=[
 {"id":"R1A-R01","target":T,"physical_case":None,"source_path":"crates/swarm-governance-witness/src/lib.rs","source_anchor":"let readiness_mode = transport_route_readiness_mode(false);","replacement":"let readiness_mode = transport_route_readiness_mode(true);","late_failure_predicate":"readiness[condition-required]"},
 {"id":"R1A-R02","target":T,"physical_case":None,"source_path":"crates/swarm-governance-witness/src/lib.rs","source_anchor":'''            (
                RuntimeRequestObservationV1::NoResponders,
                RuntimeWitnessClientErrorV1::Unavailable,
            ) => TransportRouteReadinessDispositionV1::Retry,''',"replacement":'''            (
                RuntimeRequestObservationV1::NoResponders,
                RuntimeWitnessClientErrorV1::Unavailable,
            ) => TransportRouteReadinessDispositionV1::Terminal,''',"late_failure_predicate":"readiness[no-responders-not-ready]"},
 {"id":"R1A-R03","target":T,"physical_case":None,"source_path":"crates/swarm-governance-witness/src/lib.rs","source_anchor":'''            (RuntimeRequestObservationV1::Other, RuntimeWitnessClientErrorV1::OutcomeUnknown) => {
                TransportRouteReadinessDispositionV1::Terminal
            }''',"replacement":'''            (RuntimeRequestObservationV1::Other, RuntimeWitnessClientErrorV1::OutcomeUnknown) => {
                TransportRouteReadinessDispositionV1::Retry
            }''',"late_failure_predicate":"readiness[other-terminal]"},
 {"id":"R1A-R04","target":T,"physical_case":None,"source_path":"crates/swarm-governance-witness/src/lib.rs","source_anchor":'''            (
                RuntimeRequestObservationV1::TimedOut,
                RuntimeWitnessClientErrorV1::OutcomeUnknown,
            ) => TransportRouteReadinessDispositionV1::Terminal,''',"replacement":'''            (
                RuntimeRequestObservationV1::TimedOut,
                RuntimeWitnessClientErrorV1::OutcomeUnknown,
            ) => TransportRouteReadinessDispositionV1::Retry,''',"late_failure_predicate":"readiness[timed-out-terminal]"},
 {"id":"R1A-R05","target":T,"physical_case":None,"source_path":"crates/swarm-governance-witness/src/lib.rs","source_anchor":'''        if evidence.expected_request != evidence.observed_request {
            return Err("readiness[request-bytes-correlated]");
        }''',"replacement":'''        if false && evidence.expected_request != evidence.observed_request {
            return Err("readiness[request-bytes-correlated]");
        }''',"late_failure_predicate":"readiness[request-bytes-correlated]"},
 {"id":"R1A-R06","target":T,"physical_case":None,"source_path":"crates/swarm-governance-witness/src/lib.rs","source_anchor":'''        if !readiness_reply_subject_in_namespace(&evidence.relay_routed_reply_subject, "_R_.")
            || !readiness_reply_subject_in_namespace(
                &evidence.requester_local_reply_subject,
                "_INBOX.",
            )
            || evidence.relay_routed_reply_subject == evidence.requester_local_reply_subject
        {
            return Err("readiness[reply-route-transformed]");
        }''',"replacement":'''        if false
            && (!readiness_reply_subject_in_namespace(&evidence.relay_routed_reply_subject, "_R_.")
                || !readiness_reply_subject_in_namespace(
                    &evidence.requester_local_reply_subject,
                    "_INBOX.",
                )
                || evidence.relay_routed_reply_subject == evidence.requester_local_reply_subject)
        {
            return Err("readiness[reply-route-transformed]");
        }''',"late_failure_predicate":"readiness[reply-route-transformed]"},
 {"id":"R1A-R07","target":T,"physical_case":None,"source_path":"crates/swarm-governance-witness/src/lib.rs","source_anchor":'''        if evidence.expected_response != evidence.requester_response {
            return Err("readiness[response-bytes-correlated]");
        }''',"replacement":'''        if false && evidence.expected_response != evidence.requester_response {
            return Err("readiness[response-bytes-correlated]");
        }''',"late_failure_predicate":"readiness[response-bytes-correlated]"},
 {"id":"R1A-R08","target":T,"physical_case":None,"source_path":"crates/swarm-governance-witness/src/lib.rs","source_anchor":'''        if &transport_route_readiness_receipt(evidence) != receipt {
            return Err("readiness[receipt-recomputed]");
        }''',"replacement":'''        if false && &transport_route_readiness_receipt(evidence) != receipt {
            return Err("readiness[receipt-recomputed]");
        }''',"late_failure_predicate":"readiness[receipt-recomputed]"},
]

actual=[{field:item[field] for field in identity_fields} for item in rows]
def require_frozen(candidate):
    if candidate != independent_oracle:
        raise ValueError("readiness_registry[frozen-tuple-oracle]")
require_frozen(actual)
if os.environ.get("PHASE285_R1A_SKIP_READINESS_META")!="1":
    mutations=0
    for row_index, expected_row in enumerate(independent_oracle):
        for field in identity_fields:
            mutated=[dict(item) for item in independent_oracle]
            value=expected_row[field]
            mutated[row_index][field]="held-public" if field=="physical_case" else f"{value}__readiness_meta_mutation__"
            try:
                require_frozen(mutated)
            except ValueError as error:
                if str(error)!="readiness_registry[frozen-tuple-oracle]":
                    raise SystemExit("readiness_registry[meta-wrong-predicate]") from error
            else:
                raise SystemExit(f"readiness_registry[meta-survived:{row_index}:{field}]")
            mutations+=1
    if mutations!=56:
        raise SystemExit("readiness_registry[meta-cardinality]")
    oracle_bytes=json.dumps(independent_oracle,sort_keys=True,separators=(",",":"),allow_nan=False).encode()
    print(f"transport_readiness_registry_meta rows=8 fields=7 mutations=56 failed_at_frozen_tuple=56 rust_executions=0 oracle_sha256={hashlib.sha256(oracle_bytes).hexdigest()} passed=1")

ids=[item["id"] for item in rows]
if ids!=[f"R1A-R{index:02d}" for index in range(1,9)] or len(set(ids))!=8:
    raise SystemExit("readiness_registry[set-order-cardinality]")
for item in rows:
    if item["target"]!=T or item["physical_case"] is not None or not item["source_anchor"] or item["source_anchor"]==item["replacement"]:
        raise SystemExit("readiness_registry[row]")
    if not item["late_failure_predicate"].endswith("]"):
        raise SystemExit("readiness_registry[predicate]")
encoded=json.dumps(rows,sort_keys=True,separators=(",",":"),allow_nan=False).encode()
if sys.argv[1]:
    path=pathlib.Path(sys.argv[1])
    path.write_bytes(encoded+b"\n")
    path.chmod(0o600)
print("transport_readiness_registry ids="+",".join(ids))
print(f"transport_readiness_registry rows=8 unique_ids=8 ordered=1 unique_spec_digests=8 executable=8 red=0 real_target_required=8 vacuity_classified=8 registry_sha256={hashlib.sha256(encoded).hexdigest()} passed=1")
PY
}

transport_semantics_compiled_controls() {
  local accepted_tree="$1" scratch="$2"
  local exact="$scratch/compiled-source"
  local registry="$scratch/transport-r1a-registry.json"
  mkdir -m 700 -- "$exact"
  git -C "$ROOT_DIR" archive "$accepted_tree" | tar -xf - -C "$exact"
  transport_semantics_registry_guard "$registry"
  python3 -I -u - "$exact" "$registry" <<'PY'
import hashlib,json,os,pathlib,re,shutil,subprocess,sys

template=pathlib.Path(sys.argv[1])
registry_path=pathlib.Path(sys.argv[2])
scratch=template.parent
sources_parent=scratch/"sources"
targets_parent=scratch/"targets"
if sources_parent.exists() or targets_parent.exists():
    raise SystemExit("transport_compiled[confined-roots-preexist]")
sources_parent.mkdir(mode=0o700)
targets_parent.mkdir(mode=0o700)
rows=json.loads(registry_path.read_text())
transport="service_checkpoint_transport_semantics_tests::post_command_other_is_distinct_from_pre_send_drain"
controls=[row for row in rows if row["target"]==transport and row["physical_case"] is None]
if len(controls)!=8 or any(row["execution_status"]!="executable_pending_run" for row in controls):
    raise SystemExit("transport_compiled[registry-selection]")
expected_ids=[f"R1A-C{index:02d}" for index in (1,2,9,12,13,14,15,16)]
if [row["id"] for row in controls]!=expected_ids:
    raise SystemExit("transport_compiled[registry-order]")

base=os.environ.copy()
base.pop("CARGO_TARGET_DIR",None)
base.update({"CARGO_INCREMENTAL":"0","CARGO_NET_OFFLINE":"true"})
source_digests=[]
executable_digests=[]
executable_identity_digests=[]
source_identity_digests=[]
target_identity_digests=[]
receipts=[]
for row in controls:
    source_root=sources_parent/row["id"]
    target_root=targets_parent/row["id"]
    if source_root.exists() or target_root.exists():
        raise SystemExit(f"transport_compiled[{row['id']}:identity-reuse]")
    shutil.copytree(template,source_root)
    path=source_root/row["source_path"]
    original=path.read_text()
    original_digest=hashlib.sha256(original.encode()).hexdigest()
    anchor=row["source_anchor"]
    replacement=row["replacement"]
    count=original.count(anchor)
    if count!=1:
        raise SystemExit(f"transport_compiled[{row['id']}:anchor:{count}]")
    mutant=original.replace(anchor,replacement,1)
    source_digest=hashlib.sha256(mutant.encode()).hexdigest()
    source_digests.append(source_digest)
    path.write_text(mutant)
    command=row["exact_command"]
    argv_digest=hashlib.sha256(json.dumps(command,separators=(",",":"),ensure_ascii=False).encode()).hexdigest()
    source_identity=hashlib.sha256(str(source_root.resolve()).encode()).hexdigest()
    target_identity=hashlib.sha256(str(target_root.resolve()).encode()).hexdigest()
    source_identity_digests.append(source_identity)
    target_identity_digests.append(target_identity)
    row_env=base.copy()
    row_env["CARGO_TARGET_DIR"]=str(target_root)
    print(f"transport_compiled_progress id={row['id']} target={row['target']} case=none state=start",flush=True)
    frozen_digest=None
    try:
        try:
            result=subprocess.run(
                command,
                cwd=source_root,
                env=row_env,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                timeout=180,
            )
        except subprocess.TimeoutExpired as error:
            raise SystemExit(f"transport_compiled[{row['id']}:vacuous-timeout]\n{error.stdout or ''}") from error
    finally:
        frozen_digest=hashlib.sha256(path.read_bytes()).hexdigest()
        path.write_text(original)
    output=result.stdout
    if frozen_digest!=source_digest:
        raise SystemExit(f"transport_compiled[{row['id']}:mutated-source-not-frozen]")
    if hashlib.sha256(path.read_bytes()).hexdigest()!=original_digest:
        raise SystemExit(f"transport_compiled[{row['id']}:source-not-restored]")
    running=re.findall(r"^running (\d+) tests?$",output,re.M)
    summary=re.findall(
        r"^test result: FAILED\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out;",
        output,
        re.M,
    )
    test_start=f"test {row['target']} ... "
    predicate=row["late_failure_predicate"]
    if result.returncode==0:
        raise SystemExit(f"transport_compiled[{row['id']}:survived]\n{output}")
    target_start=output.find(test_start)
    failures_start=output.find("\nfailures:\n")
    target_failed=output.find("\nFAILED\n",target_start)
    if (
        running!=["1"]
        or summary!=[("0","1","0","0","22")]
        or output.count(test_start)!=1
        or target_start<0
        or target_failed<0
        or failures_start<0
        or not target_start<target_failed<failures_start
    ):
        raise SystemExit(f"transport_compiled[{row['id']}:vacuous-real-target]\n{output}")
    predicate_position=output.find(predicate)
    first_panic=output.find("panicked at")
    summary_position=output.find("test result: FAILED.")
    if predicate_position<0 or first_panic<0 or not first_panic<predicate_position<summary_position:
        raise SystemExit(f"transport_compiled[{row['id']}:vacuous-predicate]\n{output}")
    selected_matches=re.findall(r"Running unittests src/lib\.rs \(([^)]+)\)",output)
    if len(selected_matches)!=1:
        raise SystemExit(f"transport_compiled[{row['id']}:selected-executable]\n{output}")
    selected=pathlib.Path(selected_matches[0])
    if not selected.is_file():
        raise SystemExit(f"transport_compiled[{row['id']}:selected-executable-absent]")
    try:
        selected.resolve().relative_to(target_root.resolve())
    except ValueError as error:
        raise SystemExit(f"transport_compiled[{row['id']}:selected-executable-target]") from error
    executable_digest=hashlib.sha256(selected.read_bytes()).hexdigest()
    selected_stat=selected.stat()
    executable_identity=hashlib.sha256(json.dumps(
        [str(selected.resolve()),selected_stat.st_dev,selected_stat.st_ino],
        separators=(",",":"),
    ).encode()).hexdigest()
    executable_digests.append(executable_digest)
    executable_identity_digests.append(executable_identity)
    receipt={
        "id":row["id"],
        "target":row["target"],
        "physical_case":row["physical_case"],
        "late_failure_predicate":predicate,
        "exact_argv_sha256":argv_digest,
        "mutated_source_sha256":source_digest,
        "selected_executable_sha256":executable_digest,
        "selected_executable_identity_sha256":executable_identity,
        "source_root_identity_sha256":source_identity,
        "target_root_identity_sha256":target_identity,
        "running":1,
        "passed":0,
        "failed":1,
        "ignored":0,
        "measured":0,
        "filtered_out":22,
        "compile_failure":False,
        "timeout":False,
        "generic_failure":False,
        "failure_before_named_predicate":False,
        "helper_authored_success":False,
        "vacuous":False,
    }
    receipts.append(receipt)
    print(
        f"transport_compiled_control id={row['id']} target={row['target']} case=none "
        f"running=1 passed=0 failed=1 ignored=0 measured=0 filtered_out=22 "
        f"predicate={predicate} mutated_source_sha256={source_digest} "
        f"selected_executable_sha256={executable_digest} selected_executable_identity_sha256={executable_identity} "
        f"source_root_identity_sha256={source_identity} "
        f"target_root_identity_sha256={target_identity} exact_argv_sha256={argv_digest} vacuous=0",
        flush=True,
    )
if len(set(source_digests))!=8:
    raise SystemExit("transport_compiled[mutated-source-digests]")
if len(source_identity_digests)!=8 or len(set(source_identity_digests))!=8:
    raise SystemExit("transport_compiled[source-root-identity-reuse]")
if len(target_identity_digests)!=8 or len(set(target_identity_digests))!=8:
    raise SystemExit("transport_compiled[target-root-identity-reuse]")
if len(executable_identity_digests)!=8 or len(set(executable_identity_digests))!=8:
    raise SystemExit("transport_compiled[selected-executable-identity-reuse]")
if len(receipts)!=8 or any(receipt["vacuous"] for receipt in receipts):
    raise SystemExit("transport_compiled[receipts]")
receipts_bytes=json.dumps(receipts,sort_keys=True,separators=(",",":"),allow_nan=False).encode()
print(
    "transport_semantics_compiled ids="+",".join(receipt["id"] for receipt in receipts)
    +f" mutations=8 unique_source_digests=8 unique_source_roots=8 unique_target_roots=8 selected_executables={len(executable_digests)} "
    +f"receipt_sha256={hashlib.sha256(receipts_bytes).hexdigest()} "
    +"compiled=8 executed=8 failed=8 vacuous=0 red=15 passed=1"
)

positive_source=sources_parent/"positive"
positive_target=targets_parent/"positive"
if positive_source.exists() or positive_target.exists():
    raise SystemExit("transport_positive[identity-reuse]")
shutil.copytree(template,positive_source)
positive_source_identity=hashlib.sha256(str(positive_source.resolve()).encode()).hexdigest()
positive_target_identity=hashlib.sha256(str(positive_target.resolve()).encode()).hexdigest()
if positive_source_identity in source_identity_digests or positive_target_identity in target_identity_digests:
    raise SystemExit("transport_positive[control-identity-reuse]")
positive_command=controls[0]["exact_command"]
positive_env=base.copy()
positive_env["CARGO_TARGET_DIR"]=str(positive_target)
print(f"transport_positive_progress target={transport} state=start",flush=True)
try:
    positive=subprocess.run(
        positive_command,
        cwd=positive_source,
        env=positive_env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=180,
    )
except subprocess.TimeoutExpired as error:
    raise SystemExit(f"transport_positive[timeout]\n{error.stdout or ''}") from error
positive_output=positive.stdout
positive_running=re.findall(r"^running (\d+) tests?$",positive_output,re.M)
positive_summary=re.findall(
    r"^test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out;",
    positive_output,
    re.M,
)
positive_start=f"test {transport} ... "
positive_start_position=positive_output.find(positive_start)
positive_ok_position=positive_output.find("\nok\n",positive_start_position)
positive_summary_position=positive_output.find("test result: ok.")
required_fields=("response=1","timed_out=1","no_responders=1","invalid_subject=1","post_command_other=1","shipping_other=outcome_unknown","responder_observed=1","pre_send_observed=0","relay_routed_responder=1","private_invalid_subject_invalid=1","private_malformed_invalid=1","private_operation_mismatch_invalid=1","private_digest_mismatch_invalid=1","passed=1")
marker_rows=[line for line in positive_output.splitlines() if "transport_semantics response=1" in line]
readiness_pattern=r"transport_route_readiness attempts=(\d+) no_responders=(\d+) relay_observations=1 requester_responses=1 request_correlated=1 reply_route_transformed=1 response_correlated=1 joined=1 outer_deadline_millis=5000 per_probe_deadline_millis=250 passed=1"
def normalize_readiness_rows(output):
    rows=[]
    for line in output.splitlines():
        if re.fullmatch(readiness_pattern,line):
            rows.append(line)
        elif line.startswith(positive_start) and re.fullmatch(positive_start+readiness_pattern,line):
            rows.append(line[len(positive_start):])
        elif "transport_route_readiness " in line:
            raise ValueError("transport_positive[readiness-placement]")
    if len(rows)!=1:
        raise ValueError("transport_positive[readiness-cardinality]")
    return rows
try:
    readiness_rows=normalize_readiness_rows(positive_output)
except ValueError as error:
    raise SystemExit(str(error)) from error
readiness_match=(
    re.fullmatch(
        readiness_pattern,
        readiness_rows[0],
    )
)
readiness_valid=(
    readiness_match is not None
    and int(readiness_match.group(1))>=1
    and int(readiness_match.group(1))==int(readiness_match.group(2))+1
)
if (
    positive.returncode!=0
    or positive_running!=["1"]
    or positive_summary!=[("1","0","0","0","22")]
    or positive_output.count(positive_start)!=1
    or positive_start_position<0
    or positive_ok_position<0
    or positive_summary_position<0
    or not positive_start_position<positive_ok_position<positive_summary_position
    or len(marker_rows)!=1
    or any(field not in marker_rows[0] for field in required_fields)
    or not readiness_valid
):
    raise SystemExit(f"transport_positive[real-target]\n{positive_output}")
positive_selected_matches=re.findall(r"Running unittests src/lib\.rs \(([^)]+)\)",positive_output)
if len(positive_selected_matches)!=1:
    raise SystemExit(f"transport_positive[selected-executable]\n{positive_output}")
positive_selected=pathlib.Path(positive_selected_matches[0])
if not positive_selected.is_file():
    raise SystemExit("transport_positive[selected-executable-absent]")
try:
    positive_selected.resolve().relative_to(positive_target.resolve())
except ValueError as error:
    raise SystemExit("transport_positive[selected-executable-target]") from error
positive_executable_digest=hashlib.sha256(positive_selected.read_bytes()).hexdigest()
positive_selected_stat=positive_selected.stat()
positive_executable_identity=hashlib.sha256(json.dumps(
    [str(positive_selected.resolve()),positive_selected_stat.st_dev,positive_selected_stat.st_ino],
    separators=(",",":"),
).encode()).hexdigest()
if positive_executable_identity in executable_identity_digests:
    raise SystemExit("transport_positive[control-executable-reuse]")
print(
    f"transport_positive target={transport} running=1 passed=1 failed=0 ignored=0 measured=0 filtered_out=22 "
    f"selected_executable_sha256={positive_executable_digest} selected_executable_identity_sha256={positive_executable_identity} "
    f"source_root_identity_sha256={positive_source_identity} "
    f"target_root_identity_sha256={positive_target_identity} control_source_reuse=0 control_target_reuse=0 passed_gate=1",
    flush=True,
)
PY
}

transport_positive_readiness_parser_self_test() {
  python3 -I - <<'PY'
import re

target="service_checkpoint_transport_semantics_tests::post_command_other_is_distinct_from_pre_send_drain"
prefix=f"test {target} ... "
pattern=r"transport_route_readiness attempts=(\d+) no_responders=(\d+) relay_observations=1 requester_responses=1 request_correlated=1 reply_route_transformed=1 response_correlated=1 joined=1 outer_deadline_millis=5000 per_probe_deadline_millis=250 passed=1"
marker="transport_route_readiness attempts=3 no_responders=2 relay_observations=1 requester_responses=1 request_correlated=1 reply_route_transformed=1 response_correlated=1 joined=1 outer_deadline_millis=5000 per_probe_deadline_millis=250 passed=1"

def parse(output):
    rows=[]
    for line in output.splitlines():
        if re.fullmatch(pattern,line):
            rows.append(line)
        elif line.startswith(prefix) and re.fullmatch(prefix+pattern,line):
            rows.append(line[len(prefix):])
        elif "transport_route_readiness " in line:
            raise ValueError("placement")
    if len(rows)!=1:
        raise ValueError("cardinality")
    match=re.fullmatch(pattern,rows[0])
    if match is None or int(match.group(1))<1 or int(match.group(1))!=int(match.group(2))+1:
        raise ValueError("arithmetic")
    return rows[0]

positives=[marker,prefix+marker]
for value in positives:
    parse(value)

negative_outputs=[
    "transport semantics emitted no readiness evidence",
    "test foreign::target ... "+marker,
    marker+"\n"+prefix+marker,
    " "+marker,
    marker.removesuffix(" passed=1"),
    marker+" trailing",
]
for index,value in enumerate(negative_outputs,1):
    try:
        parse(value)
    except ValueError:
        pass
    else:
        raise SystemExit(f"readiness parser negative control survived: {index}")

def legacy_standalone_only(output):
    rows=[line for line in output.splitlines() if line.startswith("transport_route_readiness ")]
    return len(rows)==1 and re.fullmatch(pattern,rows[0]) is not None
if legacy_standalone_only(prefix+marker):
    raise SystemExit("legacy inline parser mutation unexpectedly accepted inline output")

print("transport_positive_readiness_parser positives=2 controls=7 rust_executions=0 vacuous=0 passed=1")
PY
}

transport_readiness_compiled_controls() {
  local accepted_tree="$1" scratch="$2"
  local template="$scratch/readiness-template"
  local registry="$scratch/readiness-registry.json"
  mkdir -m 700 -- "$template"
  git -C "$ROOT_DIR" archive "$accepted_tree" | tar -xf - -C "$template"
  transport_readiness_registry_guard "$registry"
  python3 -I -u - "$template" "$registry" <<'PY'
import hashlib,json,os,pathlib,re,shutil,subprocess,sys

template=pathlib.Path(sys.argv[1])
registry_path=pathlib.Path(sys.argv[2])
scratch=template.parent
sources_parent=scratch/"readiness-sources"
targets_parent=scratch/"readiness-targets"
if sources_parent.exists() or targets_parent.exists():
    raise SystemExit("readiness_compiled[confined-roots-preexist]")
sources_parent.mkdir(mode=0o700)
targets_parent.mkdir(mode=0o700)
rows=json.loads(registry_path.read_text())
expected_ids=[f"R1A-R{index:02d}" for index in range(1,9)]
if [row["id"] for row in rows]!=expected_ids or any(row["execution_status"]!="executable_pending_run" for row in rows):
    raise SystemExit("readiness_compiled[registry-selection]")

base=os.environ.copy()
base.pop("CARGO_TARGET_DIR",None)
base.update({"CARGO_INCREMENTAL":"0","CARGO_NET_OFFLINE":"true"})
source_digests=[]
source_identities=[]
target_identities=[]
executable_identities=[]
receipts=[]
for row in rows:
    source_root=sources_parent/row["id"]
    target_root=targets_parent/row["id"]
    if source_root.exists() or target_root.exists():
        raise SystemExit(f"readiness_compiled[{row['id']}:identity-reuse]")
    shutil.copytree(template,source_root)
    path=source_root/row["source_path"]
    original=path.read_text()
    anchor=row["source_anchor"]
    replacement=row["replacement"]
    count=original.count(anchor)
    if count!=1:
        raise SystemExit(f"readiness_compiled[{row['id']}:anchor:{count}]")
    mutant=original.replace(anchor,replacement,1)
    path.write_text(mutant)
    source_digest=hashlib.sha256(path.read_bytes()).hexdigest()
    source_digests.append(source_digest)
    source_identity=hashlib.sha256(str(source_root.resolve()).encode()).hexdigest()
    target_identity=hashlib.sha256(str(target_root.resolve()).encode()).hexdigest()
    source_identities.append(source_identity)
    target_identities.append(target_identity)
    command=row["exact_command"]
    argv_digest=hashlib.sha256(json.dumps(command,separators=(",",":"),ensure_ascii=False).encode()).hexdigest()
    row_env=base.copy()
    row_env["CARGO_TARGET_DIR"]=str(target_root)
    print(f"readiness_compiled_progress id={row['id']} target={row['target']} case=none state=start",flush=True)
    try:
        result=subprocess.run(
            command,
            cwd=source_root,
            env=row_env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=180,
        )
    except subprocess.TimeoutExpired as error:
        raise SystemExit(f"readiness_compiled[{row['id']}:vacuous-timeout]\n{error.stdout or ''}") from error
    if hashlib.sha256(path.read_bytes()).hexdigest()!=source_digest:
        raise SystemExit(f"readiness_compiled[{row['id']}:mutated-source-not-frozen]")
    output=result.stdout
    running=re.findall(r"^running (\d+) tests?$",output,re.M)
    summary=re.findall(
        r"^test result: FAILED\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out;",
        output,
        re.M,
    )
    test_start=f"test {row['target']} ... "
    target_start=output.find(test_start)
    target_failed=output.find("\nFAILED\n",target_start)
    failures_start=output.find("\nfailures:\n")
    if (
        result.returncode==0
        or running!=["1"]
        or summary!=[("0","1","0","0","22")]
        or output.count(test_start)!=1
        or target_start<0
        or target_failed<0
        or failures_start<0
        or not target_start<target_failed<failures_start
    ):
        raise SystemExit(f"readiness_compiled[{row['id']}:vacuous-real-target]\n{output}")
    predicate=row["late_failure_predicate"]
    panic_messages=re.findall(r"panicked at [^\n]+:\n([^\n]+)",output)
    if not panic_messages or panic_messages[0].strip()!=predicate:
        raise SystemExit(f"readiness_compiled[{row['id']}:vacuous-predicate]\n{output}")
    selected_matches=re.findall(r"Running unittests src/lib\.rs \(([^)]+)\)",output)
    if len(selected_matches)!=1:
        raise SystemExit(f"readiness_compiled[{row['id']}:selected-executable]\n{output}")
    selected=pathlib.Path(selected_matches[0])
    if not selected.is_file():
        raise SystemExit(f"readiness_compiled[{row['id']}:selected-executable-absent]")
    try:
        selected.resolve().relative_to(target_root.resolve())
    except ValueError as error:
        raise SystemExit(f"readiness_compiled[{row['id']}:selected-executable-target]") from error
    executable_digest=hashlib.sha256(selected.read_bytes()).hexdigest()
    selected_stat=selected.stat()
    executable_identity=hashlib.sha256(json.dumps(
        [str(selected.resolve()),selected_stat.st_dev,selected_stat.st_ino],
        separators=(",",":"),
    ).encode()).hexdigest()
    executable_identities.append(executable_identity)
    receipt={
        "id":row["id"],
        "target":row["target"],
        "physical_case":None,
        "late_failure_predicate":predicate,
        "exact_argv_sha256":argv_digest,
        "mutated_source_sha256":source_digest,
        "selected_executable_sha256":executable_digest,
        "selected_executable_identity_sha256":executable_identity,
        "source_root_identity_sha256":source_identity,
        "target_root_identity_sha256":target_identity,
        "running":1,"passed":0,"failed":1,"ignored":0,"measured":0,"filtered_out":22,
        "compile_failure":False,"timeout":False,"generic_failure":False,
        "failure_before_named_predicate":False,"helper_authored_success":False,"vacuous":False,
    }
    receipts.append(receipt)
    print(
        f"readiness_compiled_control id={row['id']} target={row['target']} case=none "
        f"running=1 passed=0 failed=1 ignored=0 measured=0 filtered_out=22 "
        f"predicate={predicate} mutated_source_sha256={source_digest} "
        f"selected_executable_sha256={executable_digest} selected_executable_identity_sha256={executable_identity} "
        f"source_root_identity_sha256={source_identity} target_root_identity_sha256={target_identity} "
        f"exact_argv_sha256={argv_digest} vacuous=0",
        flush=True,
    )
if len(set(source_digests))!=8:
    raise SystemExit("readiness_compiled[mutated-source-digests]")
if len(set(source_identities))!=8 or len(set(target_identities))!=8 or len(set(executable_identities))!=8:
    raise SystemExit("readiness_compiled[provenance-reuse]")
receipts_bytes=json.dumps(receipts,sort_keys=True,separators=(",",":"),allow_nan=False).encode()
print(
    "transport_readiness_compiled ids="+",".join(receipt["id"] for receipt in receipts)
    +f" mutations=8 unique_source_digests=8 unique_source_roots=8 unique_target_roots=8 "
    +f"unique_executable_objects=8 receipt_sha256={hashlib.sha256(receipts_bytes).hexdigest()} "
    +"compiled=8 executed=8 failed=8 vacuous=0 passed=1"
)
PY
}

transport_semantics_held_public_compiled_controls() {
  local accepted_tree="$1" scratch="$2" requested_id="${3:-}"
  local template="$scratch/held-public-template"
  local registry="$scratch/transport-r1a-registry.json"
  mkdir -m 700 -- "$template"
  git -C "$ROOT_DIR" archive "$accepted_tree" | tar -xf - -C "$template"
  transport_semantics_registry_guard "$registry"
  python3 -I -u - "$template" "$registry" "$accepted_tree" "$requested_id" <<'PY'
import hashlib,json,os,pathlib,re,shutil,subprocess,sys

template=pathlib.Path(sys.argv[1])
registry_path=pathlib.Path(sys.argv[2])
tree=sys.argv[3]
requested_id=sys.argv[4]
scratch=template.parent
sources_parent=scratch/"grant-control-sources"
targets_parent=scratch/"grant-control-targets"
if sources_parent.exists() or targets_parent.exists():
    raise SystemExit("grant_compiled[confined-roots-preexist]")
sources_parent.mkdir(mode=0o700)
targets_parent.mkdir(mode=0o700)
rows=json.loads(registry_path.read_text())
target_name="service_checkpoint_transport_semantics_tests::public_and_private_expired_response_grants_recover_exactly_once"
controls=[row for row in rows if row["target"]==target_name and row["physical_case"]=="held-public" and row["execution_status"]=="executable_pending_run"]
expected_ids=[f"R1A-C{index:02d}" for index in (3,4,5,8,10,17,22)]
if requested_id:
    controls=[row for row in rows if row["id"]==requested_id and row["target"]==target_name and row["execution_status"]=="executable_pending_run"]
    expected_ids=[requested_id]
if [row["id"] for row in controls]!=expected_ids:
    raise SystemExit("grant_compiled[registry-selection]")
outer_token=os.environ.get("PHASE285_RELAY_TOPOLOGY_TOKEN","")
if not outer_token.startswith("relay-phase285-"):
    raise SystemExit("grant_compiled[relay-topology-token]")
base=os.environ.copy()
base.pop("CARGO_TARGET_DIR",None)
base.update({"CARGO_INCREMENTAL":"0","CARGO_NET_OFFLINE":"true"})
source_digests=[]
source_identities=[]
target_identities=[]
executable_digests=[]
executable_identity_digests=[]
process_ids=[]
token_digests=[]
receipts=[]
for ordinal,row in enumerate(controls,1):
    physical_case=row["physical_case"]
    if physical_case not in ("held-public","held-private","no-hold-public","no-hold-private"):
        raise SystemExit(f"grant_compiled[{row['id']}:physical-case]")
    source_root=sources_parent/row["id"]
    target_root=targets_parent/row["id"]
    if source_root.exists() or target_root.exists():
        raise SystemExit(f"grant_compiled[{row['id']}:identity-reuse]")
    shutil.copytree(template,source_root)
    path=source_root/row["source_path"]
    original=path.read_text()
    original_digest=hashlib.sha256(original.encode()).hexdigest()
    anchor=row["source_anchor"]
    replacement=row["replacement"]
    count=original.count(anchor)
    if count!=1:
        raise SystemExit(f"grant_compiled[{row['id']}:anchor:{count}]")
    mutant=original.replace(anchor,replacement,1)
    source_digest=hashlib.sha256(mutant.encode()).hexdigest()
    if source_digest in source_digests:
        raise SystemExit(f"grant_compiled[{row['id']}:mutated-source-reuse]")
    source_digests.append(source_digest)
    path.write_text(mutant)
    source_identity=hashlib.sha256(str(source_root.resolve()).encode()).hexdigest()
    target_identity=hashlib.sha256(str(target_root.resolve()).encode()).hexdigest()
    source_identities.append(source_identity)
    target_identities.append(target_identity)
    invocation_token=f"{outer_token}-{physical_case}-{row['id'].lower()}-{hashlib.sha256((tree+':'+row['id']).encode()).hexdigest()[:16]}"
    token_digest=hashlib.sha256(invocation_token.encode()).hexdigest()
    if token_digest in token_digests:
        raise SystemExit(f"grant_compiled[{row['id']}:invocation-token-reuse]")
    token_digests.append(token_digest)
    row_env=base.copy()
    row_env.update({"CARGO_TARGET_DIR":str(target_root),"PHASE285_RELAY_TOPOLOGY_TOKEN":invocation_token})
    command=row["exact_command"]
    argv_digest=hashlib.sha256(json.dumps(command,separators=(",",":"),ensure_ascii=False).encode()).hexdigest()
    print(f"grant_compiled_progress id={row['id']} case={physical_case} process={ordinal}/{len(controls)} state=start",flush=True)
    frozen_digest=None
    process=subprocess.Popen(
        command,cwd=source_root,env=row_env,text=True,
        stdout=subprocess.PIPE,stderr=subprocess.STDOUT,
    )
    process_ids.append(process.pid)
    try:
        output,_=process.communicate(timeout=240)
    except subprocess.TimeoutExpired as error:
        process.kill()
        output,_=process.communicate()
        frozen_digest=hashlib.sha256(path.read_bytes()).hexdigest()
        path.write_text(original)
        raise SystemExit(f"grant_compiled[{row['id']}:vacuous-timeout]\n{output}") from error
    finally:
        if frozen_digest is None:
            frozen_digest=hashlib.sha256(path.read_bytes()).hexdigest()
            path.write_text(original)
    if frozen_digest!=source_digest:
        raise SystemExit(f"grant_compiled[{row['id']}:mutated-source-not-frozen]")
    if hashlib.sha256(path.read_bytes()).hexdigest()!=original_digest:
        raise SystemExit(f"grant_compiled[{row['id']}:source-not-restored]")
    running=re.findall(r"^running (\d+) tests?$",output,re.M)
    summary=re.findall(
        r"^test result: FAILED\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out;",
        output,re.M,
    )
    test_start=f"test {target_name} ... "
    test_start_position=output.find(test_start)
    test_failed_position=output.find("\nFAILED\n",test_start_position)
    failures_position=output.find("\nfailures:\n")
    predicate=row["late_failure_predicate"]
    panic_messages=re.findall(r"panicked at [^\n]+:\n([^\n]+)",output)
    if process.returncode==0:
        raise SystemExit(f"grant_compiled[{row['id']}:survived]\n{output}")
    if (
        running!=["1"]
        or summary!=[("0","1","0","0","22")]
        or output.count(test_start)!=1
        or test_start_position<0
        or test_failed_position<0
        or failures_position<0
        or not test_start_position<test_failed_position<failures_position
    ):
        raise SystemExit(f"grant_compiled[{row['id']}:vacuous-real-target]\n{output}")
    if not panic_messages or panic_messages[0].strip()!=predicate:
        first=panic_messages[0].strip() if panic_messages else "unclassified-terminal"
        raise SystemExit(f"grant_compiled[{row['id']}:vacuous-early:{first}]\n{output}")
    selected_matches=re.findall(r"Running unittests src/lib\.rs \(([^)]+)\)",output)
    if len(selected_matches)!=1:
        raise SystemExit(f"grant_compiled[{row['id']}:selected-executable]\n{output}")
    selected=pathlib.Path(selected_matches[0])
    if not selected.is_file():
        raise SystemExit(f"grant_compiled[{row['id']}:selected-executable-absent]")
    try:
        selected.resolve().relative_to(target_root.resolve())
    except ValueError as error:
        raise SystemExit(f"grant_compiled[{row['id']}:selected-executable-target]") from error
    executable_digest=hashlib.sha256(selected.read_bytes()).hexdigest()
    selected_stat=selected.stat()
    executable_identity=hashlib.sha256(json.dumps(
        [str(selected.resolve()),selected_stat.st_dev,selected_stat.st_ino],
        separators=(",",":"),
    ).encode()).hexdigest()
    if executable_digest in executable_digests:
        raise SystemExit(f"grant_compiled[{row['id']}:selected-executable-reuse]")
    if executable_identity in executable_identity_digests:
        raise SystemExit(f"grant_compiled[{row['id']}:selected-executable-identity-reuse]")
    executable_digests.append(executable_digest)
    executable_identity_digests.append(executable_identity)
    receipt={
        "id":row["id"],"target":row["target"],"physical_case":physical_case,
        "late_failure_predicate":predicate,"process_pid":process.pid,
        "invocation_token_sha256":token_digest,"exact_argv_sha256":argv_digest,
        "mutated_source_sha256":source_digest,"selected_executable_sha256":executable_digest,
        "selected_executable_identity_sha256":executable_identity,
        "source_root_identity_sha256":source_identity,"target_root_identity_sha256":target_identity,
        "running":1,"passed":0,"failed":1,"ignored":0,"measured":0,"filtered_out":22,"vacuous":False,
    }
    receipts.append(receipt)
    print(
        f"grant_compiled_control id={row['id']} target={row['target']} case={physical_case} "
        f"process_pid={process.pid} running=1 passed=0 failed=1 ignored=0 measured=0 filtered_out=22 "
        f"predicate={predicate} mutated_source_sha256={source_digest} selected_executable_sha256={executable_digest} "
        f"selected_executable_identity_sha256={executable_identity} "
        f"source_root_identity_sha256={source_identity} target_root_identity_sha256={target_identity} "
        f"invocation_token_sha256={token_digest} exact_argv_sha256={argv_digest} vacuous=0",
        flush=True,
    )
expected_count=len(controls)
if len(receipts)!=expected_count or any(receipt["vacuous"] for receipt in receipts):
    raise SystemExit("grant_compiled[receipts]")
if len(set(source_digests))!=expected_count or len(set(source_identities))!=expected_count or len(set(target_identities))!=expected_count or len(set(executable_digests))!=expected_count or len(set(executable_identity_digests))!=expected_count or len(set(process_ids))!=expected_count or len(set(token_digests))!=expected_count:
    raise SystemExit("grant_compiled[identity-or-digest-reuse]")
receipts_bytes=json.dumps(receipts,sort_keys=True,separators=(",",":"),allow_nan=False).encode()
print(
    "transport_semantics_grant_compiled ids="+",".join(receipt["id"] for receipt in receipts)
    +f" mutations={expected_count} unique_source_digests={expected_count} unique_source_roots={expected_count} unique_target_roots={expected_count} "
    +f"unique_executables={expected_count} unique_process_ids={expected_count} unique_invocation_tokens={expected_count} "
    +f"receipt_sha256={hashlib.sha256(receipts_bytes).hexdigest()} "
    +f"compiled={expected_count} executed={expected_count} failed={expected_count} vacuous=0 remaining_red=0 passed=1"
)
PY
}

run_service_checkpoint_transport_semantics_focus() {
  local accepted_tree="${PHASE285_SERVICE_CHECKPOINT_TREE:?PHASE285_SERVICE_CHECKPOINT_TREE required}"
  local scratch
  [[ "$accepted_tree" =~ ^[0-9a-f]{40}$ ]] || { echo "service checkpoint transport tree is malformed" >&2; return 1; }
  scratch="$(phase285_create_confined_scratch phase285-transport-semantics)"
  PHASE285_WITNESS_TEMP_DIR="$scratch"
  trap cleanup_temp_dir_on_exit EXIT
  transport_semantics_registry_guard
  transport_semantics_compiled_controls "$accepted_tree" "$scratch"
  echo "service_checkpoint_transport_semantics target=T request_branches=5 private_invalid_rows=4 compiled_controls=8 red_controls=15 passed=1"
}

run_service_checkpoint_readiness_focus() {
  local accepted_tree="${PHASE285_SERVICE_CHECKPOINT_TREE:?PHASE285_SERVICE_CHECKPOINT_TREE required}"
  local scratch
  [[ "$accepted_tree" =~ ^[0-9a-f]{40}$ ]] || { echo "service checkpoint readiness tree is malformed" >&2; return 1; }
  [[ "${PHASE285_RELAY_TOPOLOGY_TOKEN:-}" == relay-phase285-* ]] || { echo "service checkpoint readiness relay topology token is absent" >&2; return 1; }
  [[ -f "${SWARM_NATS_RELAY_CREDENTIAL_PATH:-}" ]] || { echo "service checkpoint readiness relay credential is absent" >&2; return 1; }
  scratch="$(phase285_create_confined_scratch phase285-readiness-controls)"
  PHASE285_WITNESS_TEMP_DIR="$scratch"
  trap cleanup_temp_dir_on_exit EXIT
  transport_readiness_registry_guard
  transport_readiness_compiled_controls "$accepted_tree" "$scratch"
  echo "service_checkpoint_readiness target=T compiled_controls=8 registry_meta_controls=56 vacuous=0 passed=1"
}

run_service_checkpoint_held_public_controls_focus() {
  local accepted_tree="${PHASE285_SERVICE_CHECKPOINT_TREE:?PHASE285_SERVICE_CHECKPOINT_TREE required}"
  local scratch
  [[ "$accepted_tree" =~ ^[0-9a-f]{40}$ ]] || { echo "service checkpoint held-public tree is malformed" >&2; return 1; }
  [[ "${PHASE285_RELAY_TOPOLOGY_TOKEN:-}" == relay-phase285-* ]] || { echo "service checkpoint held-public relay topology token is absent" >&2; return 1; }
  [[ -f "${SWARM_NATS_RELAY_CREDENTIAL_PATH:-}" ]] || { echo "service checkpoint held-public relay credential is absent" >&2; return 1; }
  scratch="$(phase285_create_confined_scratch phase285-held-public-controls)"
  PHASE285_WITNESS_TEMP_DIR="$scratch"
  trap cleanup_temp_dir_on_exit EXIT
  transport_semantics_registry_guard
  transport_semantics_held_public_compiled_controls "$accepted_tree" "$scratch"
  echo "service_checkpoint_held_public_controls target=G case=held-public compiled_controls=7 remaining_red_controls=0 passed=1"
}

run_service_checkpoint_r1a_control_focus() {
  local control_id="${1:?control ID required}"
  local accepted_tree="${PHASE285_SERVICE_CHECKPOINT_TREE:?PHASE285_SERVICE_CHECKPOINT_TREE required}"
  local scratch
  case "$control_id" in R1A-C03|R1A-C04|R1A-C05|R1A-C06|R1A-C07|R1A-C08|R1A-C10|R1A-C11|R1A-C17|R1A-C18|R1A-C19|R1A-C20|R1A-C21|R1A-C22|R1A-C23) ;; *) echo "unsupported isolated R1a control: $control_id" >&2; return 2 ;; esac
  [[ "$accepted_tree" =~ ^[0-9a-f]{40}$ ]] || { echo "service checkpoint R1a control tree is malformed" >&2; return 1; }
  [[ "${PHASE285_RELAY_TOPOLOGY_TOKEN:-}" == relay-phase285-* ]] || { echo "service checkpoint R1a control relay topology token is absent" >&2; return 1; }
  [[ -f "${SWARM_NATS_RELAY_CREDENTIAL_PATH:-}" ]] || { echo "service checkpoint R1a control relay credential is absent" >&2; return 1; }
  scratch="$(phase285_create_confined_scratch phase285-r1a-control)"
  PHASE285_WITNESS_TEMP_DIR="$scratch"
  trap cleanup_temp_dir_on_exit EXIT
  transport_semantics_held_public_compiled_controls "$accepted_tree" "$scratch" "$control_id"
  echo "service_checkpoint_r1a_control id=$control_id compiled_controls=1 remaining_red_controls=0 passed=1"
}

run_service_checkpoint_grant_recovery_positive_focus() {
  local accepted_tree="${PHASE285_SERVICE_CHECKPOINT_TREE:?PHASE285_SERVICE_CHECKPOINT_TREE required}"
  local scratch case source target
  [[ "$accepted_tree" =~ ^[0-9a-f]{40}$ ]] || { echo "service checkpoint grant-recovery tree is malformed" >&2; return 1; }
  [[ "${PHASE285_RELAY_TOPOLOGY_TOKEN:-}" == relay-phase285-* ]] || { echo "service checkpoint grant-recovery relay topology token is absent" >&2; return 1; }
  [[ -f "${SWARM_NATS_RELAY_CREDENTIAL_PATH:-}" ]] || { echo "service checkpoint grant-recovery relay credential is absent" >&2; return 1; }
  scratch="$(phase285_create_confined_scratch phase285-grant-recovery-positive)"
  PHASE285_WITNESS_TEMP_DIR="$scratch"
  trap cleanup_temp_dir_on_exit EXIT
  for case in held-public held-private no-hold-public no-hold-private; do
    source="$scratch/grant-positive-source-$case"
    target="$scratch/grant-positive-target-$case"
    [[ ! -e "$source" && ! -e "$target" ]] || { echo "service checkpoint grant-recovery positive roots preexist" >&2; return 1; }
    mkdir -m 700 -- "$source"
    git -C "$ROOT_DIR" archive "$accepted_tree" | tar -xf - -C "$source"
  done
  python3 -I -u - "$scratch" "$accepted_tree" "$PHASE285_RELAY_TOPOLOGY_TOKEN" <<'PY'
import hashlib,json,os,pathlib,re,subprocess,sys

scratch=pathlib.Path(sys.argv[1])
tree=sys.argv[2]
outer_token=sys.argv[3]
test_name="service_checkpoint_transport_semantics_tests::public_and_private_expired_response_grants_recover_exactly_once"
cases=("held-public","held-private","no-hold-public","no-hold-private")
owned=(
    "crates/swarm-governance-witness/src/lib.rs",
    "crates/swarm-governance-witness/src/public_dispatcher.rs",
    "crates/swarm-governance-witness/src/runtime_client.rs",
    "crates/swarm-governance-witness/src/service_config.rs",
    "crates/swarm-governance-witness/src/store_proxy_service.rs",
    "tools/check-phase285-witness-conformance.sh",
    "tools/fixtures/phase285-witness-integrity.json",
)
if not outer_token.startswith("relay-phase285-"):
    raise SystemExit("grant_positive[relay-topology-token]")
def source_snapshot(source):
    rows=[]
    for relative in owned:
        path=source/relative
        data=path.read_bytes()
        rows.append((relative,hashlib.sha256(data).hexdigest(),len(data)))
    return hashlib.sha256(json.dumps(rows,separators=(",",":"),ensure_ascii=False).encode()).hexdigest()
def object_identity(path):
    resolved=path.resolve(strict=True)
    metadata=resolved.stat()
    return hashlib.sha256(json.dumps(
        [str(resolved),metadata.st_dev,metadata.st_ino],
        separators=(",",":"),
    ).encode()).hexdigest()
base=os.environ.copy()
base.pop("CARGO_TARGET_DIR",None)
base.update({"CARGO_INCREMENTAL":"0","CARGO_NET_OFFLINE":"true"})
build_command=[
    "cargo","test","-p","swarm-governance-witness","--lib","--locked","--offline","--no-run",test_name,
]
source_identities=[]
target_identities=[]
executable_identities=[]
process_ids=[]
token_digests=[]
case_receipts=[]
for index,case in enumerate(cases,1):
    source=scratch/f"grant-positive-source-{case}"
    target=scratch/f"grant-positive-target-{case}"
    if not source.is_dir() or target.exists():
        raise SystemExit(f"grant_positive[{case}:initial-root-identity]")
    source_identity=object_identity(source)
    if source_identity in source_identities:
        raise SystemExit(f"grant_positive[{case}:source-root-reuse]")
    source_identities.append(source_identity)
    clean_source_digest=source_snapshot(source)
    build_env=base.copy()
    build_env["CARGO_TARGET_DIR"]=str(target)
    print(
        f"grant_positive_build case={case} target={test_name} source_root_state=git_archive "
        "target_root_state=absent state=start",
        flush=True,
    )
    try:
        build=subprocess.run(
            build_command,cwd=source,env=build_env,text=True,
            stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=240,
        )
    except subprocess.TimeoutExpired as error:
        raise SystemExit(f"grant_positive[{case}:build-timeout]\n{error.stdout or ''}") from error
    if build.returncode!=0:
        raise SystemExit(f"grant_positive[{case}:build-failure]\n{build.stdout}")
    matches=re.findall(r"Executable unittests src/lib\.rs \(([^)]+)\)",build.stdout)
    if len(matches)!=1:
        raise SystemExit(f"grant_positive[{case}:build-executable]\n{build.stdout}")
    selected=pathlib.Path(matches[0])
    if not selected.is_file() or not target.is_dir():
        raise SystemExit(f"grant_positive[{case}:build-executable-absent]")
    try:
        selected.resolve().relative_to(target.resolve())
    except ValueError as error:
        raise SystemExit(f"grant_positive[{case}:build-executable-target]") from error
    target_identity=object_identity(target)
    selected_identity=object_identity(selected)
    if target_identity in target_identities:
        raise SystemExit(f"grant_positive[{case}:target-root-reuse]")
    if selected_identity in executable_identities:
        raise SystemExit(f"grant_positive[{case}:selected-executable-reuse]")
    target_identities.append(target_identity)
    executable_identities.append(selected_identity)
    selected_digest=hashlib.sha256(selected.read_bytes()).hexdigest()
    if source_snapshot(source)!=clean_source_digest:
        raise SystemExit(f"grant_positive[{case}:build-mutated-source]")
    print(
        f"grant_positive_build case={case} target={test_name} builds=1 selected_executable_sha256={selected_digest} "
        f"selected_executable_identity_sha256={selected_identity} source_snapshot_sha256={clean_source_digest} "
        f"source_root_identity_sha256={source_identity} target_root_identity_sha256={target_identity} passed=1",
        flush=True,
    )
    invocation_token=f"{outer_token}-r1a-positive-{case}-{hashlib.sha256((tree+':'+case).encode()).hexdigest()[:16]}"
    token_digest=hashlib.sha256(invocation_token.encode()).hexdigest()
    if token_digest in token_digests:
        raise SystemExit(f"grant_positive[{case}:invocation-token-reuse]")
    token_digests.append(token_digest)
    case_env=base.copy()
    case_env.update({
        "CARGO_TARGET_DIR":str(target),
        "PHASE285_R1A_GRANT_CASE":case,
        "PHASE285_RELAY_TOPOLOGY_TOKEN":invocation_token,
    })
    command=[str(selected),test_name,"--ignored","--exact","--nocapture","--test-threads=1"]
    argv_digest=hashlib.sha256(json.dumps(command,separators=(",",":"),ensure_ascii=False).encode()).hexdigest()
    print(f"grant_positive_progress case={case} process={index}/4 state=start",flush=True)
    process=subprocess.Popen(
        command,cwd=source,env=case_env,text=True,
        stdout=subprocess.PIPE,stderr=subprocess.STDOUT,
    )
    process_ids.append(process.pid)
    try:
        output,_=process.communicate(timeout=180)
    except subprocess.TimeoutExpired as error:
        process.kill()
        output,_=process.communicate()
        raise SystemExit(f"grant_positive[{case}:timeout]\n{output}") from error
    running=re.findall(r"^running (\d+) tests?$",output,re.M)
    summary=re.findall(
        r"^test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out;",
        output,re.M,
    )
    test_start=f"test {test_name} ... "
    test_start_position=output.find(test_start)
    test_ok_position=output.find("\nok\n",test_start_position)
    summary_position=output.find("test result: ok.")
    marker_rows=[line for line in output.splitlines() if "response_grant_recovery " in line]
    common=(
        f"physical_case={case}","relay_path=1","first_payload_captured=1",
        "terminal_attempts=1","terminal_applied=1","additional_cas_applied=0","passed=1",
    )
    if case.startswith("held-"):
        required=common+(
            "mode=Held","held_past_grant=1","outcome_unknown=1",
            "broker_late_publish_refused=1","exact_reply_bound=1","unrelated_refusal_rejected=1",
            "pre_recovery_attempts=1","pre_recovery_applied=1",
            "post_recovery_attempts=1","post_recovery_applied=1",
            "recovery_delta_attempts=0","recovery_delta_applied=0",
            "stale_service_atomic_delta_attempts=0","stale_service_atomic_delta_applied=0",
            "stale_service_refused_conflict=1","no_hold_reply=0",
        )
        if case=="held-public":
            required+=("leg=Public","public_lost_replay_bytes_identical=1","operand_receipt_digest=")
        else:
            required+=(
                "leg=Private","private_cas_applied_bound=1","stored_envelope_bound=1",
                "rotation_receipt_bound=1","public_replays_identical=1",
                "cross_layer_bytes_compared=0","private_join_receipt_digest=",
            )
    else:
        required=common+("mode=NoHold","no_hold_reply=1","parent_join_digest=")
        if case=="no-hold-public":
            required+=("leg=Public","public_capture_delivered_identical=1")
        else:
            required+=(
                "leg=Private","private_cas_applied_bound=1","stored_envelope_bound=1",
                "rotation_receipt_bound=1","outer_attestation_bound=1","cross_layer_bytes_compared=0",
            )
    marker=marker_rows[0] if len(marker_rows)==1 else ""
    digest_fields=re.findall(r"(?:operand_receipt_digest|private_join_receipt_digest|parent_join_digest)=([0-9a-f]{64})",marker)
    expected_digest_fields=1
    transcript_valid=(
        process.returncode==0
        and running==["1"]
        and summary==[("1","0","0","0","22")]
        and output.count(test_start)==1
        and test_start_position>=0
        and test_ok_position>=0
        and summary_position>=0
        and test_start_position<test_ok_position<summary_position
        and len(marker_rows)==1
        and all(field in marker for field in required)
        and len(digest_fields)==expected_digest_fields
    )
    if not transcript_valid:
        panics=re.findall(r"panicked at [^\n]+:\n([^\n]+)",output)
        predicate=panics[0].strip() if panics else "unclassified-terminal"
        raise SystemExit(f"grant_positive[{case}:red:{predicate}]\n{output}")
    if source_snapshot(source)!=clean_source_digest:
        raise SystemExit(f"grant_positive[{case}:run-mutated-source]")
    receipt={
        "case":case,"process_pid":process.pid,"invocation_token_sha256":token_digest,
        "exact_argv_sha256":argv_digest,"selected_executable_sha256":selected_digest,
        "selected_executable_identity_sha256":selected_identity,
        "source_root_identity_sha256":source_identity,
        "target_root_identity_sha256":target_identity,
        "source_snapshot_sha256":clean_source_digest,
        "running":1,"passed":1,"failed":0,"ignored":0,"measured":0,"filtered_out":22,
        "terminal_marker_sha256":hashlib.sha256(marker.encode()).hexdigest(),
    }
    case_receipts.append(receipt)
    print(
        f"grant_positive_case case={case} process_pid={process.pid} invocation_token_sha256={token_digest} "
        f"running=1 passed=1 failed=0 ignored=0 measured=0 filtered_out=22 "
        f"terminal_marker_sha256={receipt['terminal_marker_sha256']} selected_executable_sha256={selected_digest} "
        f"selected_executable_identity_sha256={selected_identity} source_root_identity_sha256={source_identity} "
        f"target_root_identity_sha256={target_identity} source_snapshot_sha256={clean_source_digest} "
        f"archive_tree={tree} passed_gate=1",
        flush=True,
    )
if len(process_ids)!=4 or len(set(process_ids))!=4:
    raise SystemExit("grant_positive[physical-process-reuse]")
if len(token_digests)!=4 or len(set(token_digests))!=4:
    raise SystemExit("grant_positive[invocation-token-reuse]")
if len(source_identities)!=4 or len(set(source_identities))!=4:
    raise SystemExit("grant_positive[source-root-reuse]")
if len(target_identities)!=4 or len(set(target_identities))!=4:
    raise SystemExit("grant_positive[target-root-reuse]")
if len(executable_identities)!=4 or len(set(executable_identities))!=4:
    raise SystemExit("grant_positive[selected-executable-reuse]")
receipts_bytes=json.dumps(case_receipts,sort_keys=True,separators=(",",":"),allow_nan=False).encode()
print(
    f"service_checkpoint_grant_recovery_positive target=G builds=4 archive_sources=4 initially_absent_targets=4 "
    f"physical_processes=4 unique_process_ids=4 unique_invocation_tokens=4 unique_source_roots=4 "
    f"unique_target_roots=4 unique_executable_objects=4 cases=held-public,held-private,no-hold-public,no-hold-private "
    f"running=4 passed=4 failed=0 ignored=0 measured=0 filtered_out=88 "
    f"receipt_sha256={hashlib.sha256(receipts_bytes).hexdigest()} cross_layer_bytes_compared=0 passed_gate=1"
)
PY
}

run_service_checkpoint_r1a_corpus() {
  local accepted_tree="${PHASE285_SERVICE_CHECKPOINT_TREE:?PHASE285_SERVICE_CHECKPOINT_TREE required}"
  local scratch transcript registry control_id
  [[ "$accepted_tree" =~ ^[0-9a-f]{40}$ ]] || { echo "service checkpoint R1a corpus tree is malformed" >&2; return 1; }
  [[ "${PHASE285_RELAY_TOPOLOGY_TOKEN:-}" == relay-phase285-* ]] || { echo "service checkpoint R1a corpus relay topology token is absent" >&2; return 1; }
  [[ -f "${SWARM_NATS_RELAY_CREDENTIAL_PATH:-}" ]] || { echo "service checkpoint R1a corpus relay credential is absent" >&2; return 1; }
  scratch="$(phase285_create_confined_scratch phase285-r1a-corpus)"
  PHASE285_WITNESS_TEMP_DIR="$scratch"
  trap cleanup_temp_dir_on_exit EXIT
  transcript="$scratch/corpus.txt"
  registry="$scratch/registry.json"
  transport_semantics_registry_guard "$registry" 2>&1 | tee -a "$transcript"
  transport_readiness_registry_guard 2>&1 | tee -a "$transcript"
  export PHASE285_R1A_SKIP_REGISTRY_META=1
  export PHASE285_R1A_SKIP_READINESS_META=1
  (
    run_service_checkpoint_transport_semantics_focus
  ) 2>&1 | tee -a "$transcript"
  (
    run_service_checkpoint_readiness_focus
  ) 2>&1 | tee -a "$transcript"
  (
    run_service_checkpoint_grant_recovery_positive_focus
  ) 2>&1 | tee -a "$transcript"
  for control_id in R1A-C03 R1A-C04 R1A-C05 R1A-C06 R1A-C07 R1A-C08 R1A-C10 R1A-C11 R1A-C17 R1A-C18 R1A-C19 R1A-C20 R1A-C21 R1A-C22 R1A-C23; do
    (
      run_service_checkpoint_r1a_control_focus "$control_id"
    ) 2>&1 | tee -a "$transcript"
  done
  unset PHASE285_R1A_SKIP_REGISTRY_META
  unset PHASE285_R1A_SKIP_READINESS_META
  python3 -I -u - "$transcript" "$accepted_tree" <<'PY'
import hashlib,json,pathlib,re,sys

transcript=pathlib.Path(sys.argv[1]).read_text()
tree=sys.argv[2]
lines=transcript.splitlines()
meta=[line for line in lines if line.startswith("transport_semantics_registry_meta ")]
if len(meta)!=1 or not all(field in meta[0] for field in (
    "rows=23","fields=7","mutations=161","failed_at_frozen_tuple=161",
    "rust_executions=0","passed=1",
)):
    raise SystemExit("r1a_corpus[registry-meta]")
readiness_meta=[line for line in lines if line.startswith("transport_readiness_registry_meta ")]
if len(readiness_meta)!=1 or not all(field in readiness_meta[0] for field in (
    "rows=8","fields=7","mutations=56","failed_at_frozen_tuple=56",
    "rust_executions=0","passed=1",
)):
    raise SystemExit("r1a_corpus[readiness-registry-meta]")
t_rows=[line for line in lines if line.startswith("transport_compiled_control ")]
g_rows=[line for line in lines if line.startswith("grant_compiled_control ")]
readiness_rows=[line for line in lines if line.startswith("readiness_compiled_control ")]
positive_rows=[line for line in lines if line.startswith("grant_positive_case ")]
expected_t=[f"R1A-C{index:02d}" for index in (1,2,9,12,13,14,15,16)]
expected_g=[f"R1A-C{index:02d}" for index in (3,4,5,6,7,8,10,11,17,18,19,20,21,22,23)]
expected_readiness=[f"R1A-R{index:02d}" for index in range(1,9)]

def field(line,name):
    match=re.search(rf"(?:^| ){re.escape(name)}=([^ ]+)",line)
    if match is None:
        raise SystemExit(f"r1a_corpus[missing-field:{name}]")
    return match.group(1)

if [field(line,"id") for line in t_rows]!=expected_t:
    raise SystemExit("r1a_corpus[t-control-set]")
if [field(line,"id") for line in g_rows]!=expected_g:
    raise SystemExit("r1a_corpus[g-control-set]")
if [field(line,"id") for line in readiness_rows]!=expected_readiness:
    raise SystemExit("r1a_corpus[readiness-control-set]")
expected_cases=["held-public","held-private","no-hold-public","no-hold-private"]
if [field(line,"case") for line in positive_rows]!=expected_cases:
    raise SystemExit("r1a_corpus[positive-cases]")
if any(field(line,"vacuous")!="0" for line in [*t_rows,*g_rows,*readiness_rows]):
    raise SystemExit("r1a_corpus[vacuous-control]")
if any(field(line,"passed_gate")!="1" or field(line,"archive_tree")!=tree for line in positive_rows):
    raise SystemExit("r1a_corpus[positive-binding]")
receipts=[*t_rows,*g_rows,*readiness_rows,*positive_rows]
if len(receipts)!=35:
    raise SystemExit("r1a_corpus[execution-cardinality]")
identity_fields=(
    "source_root_identity_sha256",
    "target_root_identity_sha256",
    "selected_executable_identity_sha256",
)
for identity_field in identity_fields:
    values=[field(line,identity_field) for line in receipts]
    if any(re.fullmatch(r"[0-9a-f]{64}",value) is None for value in values):
        raise SystemExit(f"r1a_corpus[{identity_field}-format]")
    if len(set(values))!=35:
        raise SystemExit(f"r1a_corpus[{identity_field}-reuse]")
if not any(line.startswith("transport_positive ") and "passed_gate=1" in line for line in lines):
    raise SystemExit("r1a_corpus[transport-positive]")
if not any(line.startswith("service_checkpoint_grant_recovery_positive ") and "builds=4" in line and "passed_gate=1" in line for line in lines):
    raise SystemExit("r1a_corpus[grant-positives]")
receipt_bytes=json.dumps(receipts,separators=(",",":"),ensure_ascii=False).encode()
print(
    "service_checkpoint_r1a_corpus positives=4/4 t_controls=8/8 g_controls=15/15 readiness_controls=8/8 "
    "registry_meta_controls=217/217 provenance_executions=35 unique_source_roots=35 "
    "unique_target_roots=35 unique_executable_objects=35 reused_provenance=0 vacuous=0 "
    f"receipt_sha256={hashlib.sha256(receipt_bytes).hexdigest()} passed=1"
)
PY
}

run_service_checkpoint_grant_focus() {
  local accepted_tree="${PHASE285_SERVICE_CHECKPOINT_TREE:?PHASE285_SERVICE_CHECKPOINT_TREE required}"
  local scratch ledger output list_output mode
  [[ "$accepted_tree" =~ ^[0-9a-f]{40}$ ]] || { echo "service checkpoint grant tree is malformed" >&2; return 1; }
  scratch="$(phase285_create_confined_scratch phase285-grants)"
  PHASE285_WITNESS_TEMP_DIR="$scratch"
  trap cleanup_temp_dir_on_exit EXIT
  ledger="$scratch/grants.json"
  output="$scratch/grants.txt"
  list_output="$scratch/grants-list.txt"
  cargo test -p swarm-governance-witness --lib --locked --offline -- --list >"$list_output"
  PHASE285_GRANT_ONLY=1 PHASE285_GRANT_LEDGER="$ledger" \
  PHASE285_SERVICE_CHECKPOINT_TREE="$accepted_tree" \
    cargo test -p swarm-governance-witness --lib --locked --offline -- --test-threads=1 --ignored \
      service_checkpoint_relay_tests::complete_receipt_authority_and_grants_are_observed --exact | tee "$output"
  validate_service_checkpoint_exact_test "$output" "$list_output" \
    service_checkpoint_relay_tests::complete_receipt_authority_and_grants_are_observed \
    'test service_checkpoint_relay_tests::complete_receipt_authority_and_grants_are_observed ... ok'
  mode=normal
  if [ -n "${PHASE285_RELAY_TOPOLOGY_TOKEN:-}" ]; then
    mode=relay
  fi
  validate_service_checkpoint_grant_ledger "$ledger" "$accepted_tree" "$mode"
}

relay_recreation_canonical_route_guard() {
  python3 -I - "$ROOT_DIR/tools/check-phase285-witness-conformance.sh" "${1:-normal}" <<'PY'
import hashlib, pathlib, re, sys

source = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
mode = sys.argv[2]
route_pattern = re.compile(
    r"(?ms)^ci_harness_dispatch_route\(\) \{\n(?P<body>.*?)^\}\n"
)
required = (
    "    receipt-topology)\n"
    "      topology_owner_block_focus\n"
    "      run_relay_recreation_mutants_for_ci\n"
    "      ;;\n"
)

def validate(candidate):
    matches = list(route_pattern.finditer(candidate))
    if len(matches) != 1:
        raise ValueError("dispatch-function-cardinality")
    body = matches[0].group("body")
    if body.count("receipt-topology)") != 1 or body.count(required) != 1:
        raise ValueError("receipt-topology-contract")
    if body.count("topology_owner_block_focus") != 1:
        raise ValueError("receipt-topology-positive-cardinality")
    if body.count("run_relay_recreation_mutants_for_ci") != 1:
        raise ValueError("receipt-topology-mutant-cardinality")

validate(source)
if mode == "self-test":
    mutants = [
        (
            "omit-canonical-mutants",
            required,
            required.replace("      run_relay_recreation_mutants_for_ci\n", "", 1),
        ),
        (
            "reorder-before-positive",
            required,
            (
                "    receipt-topology)\n"
                "      run_relay_recreation_mutants_for_ci\n"
                "      topology_owner_block_focus\n"
                "      ;;\n"
            ),
        ),
    ]
    digests = []
    for name, old, new in mutants:
        if source.count(old) != 1:
            raise SystemExit(f"relay_recreation_canonical_route_guard[anchor:{name}]")
        candidate = source.replace(old, new, 1)
        digests.append(hashlib.sha256(candidate.encode()).hexdigest())
        try:
            validate(candidate)
        except ValueError as error:
            if str(error) != "receipt-topology-contract":
                raise SystemExit(
                    f"relay_recreation_canonical_route_guard[wrong-reason:{name}:{error}]"
                )
            print(
                "relay_recreation_canonical_route_mutation_red "
                f"mutation={name} reason=receipt-topology-contract"
            )
        else:
            raise SystemExit(
                f"relay_recreation_canonical_route_guard[survived:{name}]"
            )
    if len(set(digests)) != len(mutants):
        raise SystemExit("relay_recreation_canonical_route_guard[digest-reuse]")
    print(
        "relay_recreation_canonical_route_guard "
        f"mutations={len(mutants)} unique={len(set(digests))} passed=1"
    )
elif mode == "normal":
    print("relay_recreation_canonical_route_guard passed=1")
else:
    raise SystemExit(f"relay_recreation_canonical_route_guard[mode:{mode}]")
PY
}

relay_recreation_source_guard() {
  relay_recreation_canonical_route_guard normal
  python3 -I - \
    "$ROOT_DIR/crates/swarm-governance-witness/src/lib.rs" \
    "$ROOT_DIR/crates/swarm-governance-witness/src/runtime_client.rs" \
    "$ROOT_DIR/tools/check-phase285-witness-conformance.sh" <<'PY'
import pathlib, sys
library, runtime, conformance = (
    pathlib.Path(value).read_text(encoding="utf-8") for value in sys.argv[1:]
)
required_library = [
    "async fn stop_and_confirm(mut self)",
    "Ok(Err(error)) if error.is_cancelled()",
    "tokio::time::timeout_at(shutdown_deadline, self.public_client.drain())",
    "tokio::time::timeout_at(shutdown_deadline, self.private_client.drain())",
    "let task_inventory_valid = self.tasks.len() == 12;",
    "let mut task_joins_valid = true;",
    "let identities_absent =",
    'format!("{monitor_url}/connz?auth=1&subs=1")',
    "async fn await_relay_subject_sets(",
    "public_subjects == expected_public && private_subjects == expected_private",
    'panic!("relay first-request timestamp overflow")',
    "relay_recreation_errors no_responders=1 no_responders_unavailable=1 post_accept_other=1 post_accept_other_outcome_unknown=1 rejected_as_replay=2 passed=1",
    "relay_recreation_teardown tasks_joined={} old_absent={} drained={} passed=1",
    "relay_recreation_readiness delayed_pending=1 new_present={} public_subscriptions={} private_subscriptions={} wildcard={} passed=1",
    "relay_recreation_startup_failure public_tasks_spawned=0 private_tasks_spawned=0 identities_absent=2 passed=1",
    "relay_replay_request_outcome kind=response passed=1",
]
required_runtime = [
    "RequestErrorKind::NoResponders => RuntimeWitnessClientErrorV1::Unavailable",
    "RequestErrorKind::Other => RuntimeWitnessClientErrorV1::OutcomeUnknown",
    "pub(crate) const fn is_replay_response(self) -> bool",
    "matches!(self, Self::Response)",
    '#[error("runtime witness request has unknown outcome")]',
]
for fragment in required_library:
    if library.count(fragment) != 1:
        raise SystemExit(f"relay_recreation_source_guard[library:{fragment[:48]}:{library.count(fragment)}]")
for fragment in required_runtime:
    if runtime.count(fragment) != 1:
        raise SystemExit(f"relay_recreation_source_guard[runtime:{fragment[:48]}:{runtime.count(fragment)}]")
exact_public_subjects = [
    "swarm.governance.witness.relay.v1.fence",
    "swarm.governance.witness.relay.v1.establish",
    "swarm.governance.witness.relay.v1.discover",
    "swarm.governance.witness.relay.v1.prepare",
    "swarm.governance.witness.relay.v1.commit",
    "swarm.governance.witness.relay.v1.abort",
    "swarm.governance.witness.relay.v1.read_prepared",
    "swarm.governance.witness.relay.v1.read_head",
    "swarm.governance.witness.relay.v1.fetch_payload",
]
exact_private_subjects = [
    "swarm.governance.witness.relay.store.v1.inspect_ready",
    "swarm.governance.witness.relay.store.v1.read_entry",
    "swarm.governance.witness.relay.store.v1.compare_and_swap",
]
public_expected_region = library.split(
    "fn exact_public_relay_subjects() -> BTreeSet<String>", 1
)[1].split("fn exact_private_relay_subjects() -> BTreeSet<String>", 1)[0]
private_expected_region = library.split(
    "fn exact_private_relay_subjects() -> BTreeSet<String>", 1
)[1].split("fn relay_connz()", 1)[0]
for subject in exact_public_subjects:
    if public_expected_region.count(f'"{subject}".to_string()') != 1:
        raise SystemExit(f"relay_recreation_source_guard[exact-public-subject:{subject}]")
for subject in exact_private_subjects:
    if private_expected_region.count(f'"{subject}".to_string()') != 1:
        raise SystemExit(f"relay_recreation_source_guard[exact-private-subject:{subject}]")

def validate_observation_binding(source):
    if (
        source.count("fn relay_curl_path() -> ProtocolResult<PathBuf>") != 1
        or source.count('std::env::var("PHASE285_CONNZ_CURL_BIN")') != 1
        or source.count("Command::new(relay_curl_path()?)") != 1
    ):
        raise ValueError("root-curl-binding")
    observation_region = source.split("fn server_connection_observation(", 1)[1].split(
        "fn runtime_observation_config()", 1
    )[0]
    observation_fragments = (
        "let response = must(relay_connz(),",
        "relay_connz_records(&response)",
        "relay_record_for_client_id(connections, server_client_id)",
    )
    if any(observation_region.count(fragment) != 1 for fragment in observation_fragments):
        raise ValueError("strict-connz-observation")
    if ".find(" in observation_region or "subs=0" in observation_region:
        raise ValueError("strict-connz-observation")
    curl_region = source.split("fn relay_curl_path()", 1)[1].split(
        "fn relay_connz_records(", 1
    )[0]
    curl_fragments = (
        'std::env::var("PHASE285_CONNZ_CURL_BIN")',
        "if !path.is_absolute()",
        "metadata.file_type().is_symlink()",
        "!metadata.is_file()",
        "metadata.mode() & 0o111 == 0",
        "if canonical != path",
        "Command::new(relay_curl_path()?)",
    )
    if any(curl_region.count(fragment) != 1 for fragment in curl_fragments):
        raise ValueError("root-curl-binding")
    if 'Command::new("curl")' in source:
        raise ValueError("root-curl-binding")
    bounded_capture_fragments = (
        "fn read_relay_command_pipe<R: Read>(",
        '"--max-filesize"',
        ".stdout(std::process::Stdio::piped())",
        ".stderr(std::process::Stdio::piped())",
        "overflow_rx.recv_timeout(Duration::from_millis(10))",
        "|| stdout_exceeded",
        "|| stderr_exceeded",
        "let _ = child.kill();",
        "let _ = child.wait();",
    )
    if any(fragment not in curl_region for fragment in bounded_capture_fragments):
        raise ValueError("bounded-connz-capture")

validate_observation_binding(library)
observation_mutants = (
    (
        "weak-first-match",
        "relay_record_for_client_id(connections, server_client_id)",
        "Ok(connections.first())",
        "strict-connz-observation",
    ),
    (
        "ambient-curl",
        "Command::new(relay_curl_path()?)",
        'Command::new("curl")',
        "root-curl-binding",
    ),
    (
        "unbounded-capture",
        '"--max-filesize"',
        '"--compressed"',
        "bounded-connz-capture",
    ),
)
for name, old, new, expected in observation_mutants:
    if library.count(old) != 1:
        raise SystemExit(f"relay_recreation_source_guard[observation-anchor:{name}]")
    candidate = library.replace(old, new, 1)
    try:
        validate_observation_binding(candidate)
    except ValueError as error:
        if str(error) != expected:
            raise SystemExit(
                f"relay_recreation_source_guard[observation-wrong-reason:{name}:{error}]"
            )
    else:
        raise SystemExit(f"relay_recreation_source_guard[observation-survived:{name}]")
print(
    "relay_recreation_observation_mutations "
    "strict_connz=1 root_curl=1 bounded_capture=1 passed=1"
)
connz_region = library.split(
    "fn relay_connz_records(value: &serde_json::Value)", 1
)[1].split("fn relay_record_subjects(", 1)[0]
complete_connz_counts = {
    'get("offset")': 1, 'get("total")': 1, 'get("limit")': 1,
    'get("num_connections")': 1, "offset != 0": 1,
    "total != num_connections": 1, "num_connections != observed": 1,
    "limit < total": 1, "client_id == 0": 2,
    "!client_ids.insert(client_id)": 1, "fn relay_record_for_client_id": 1,
    "if matches.next().is_some()": 1,
}
for fragment, expected in complete_connz_counts.items():
    if connz_region.count(fragment) != expected:
        raise SystemExit(f"relay_recreation_source_guard[complete-connz:{fragment}]")
if ".find(" in connz_region:
    raise SystemExit("relay_recreation_source_guard[connz-first-match]")
stop_region = library.split("async fn stop_and_confirm(mut self)", 1)[1].split(
    "async fn abort_only_for_control", 1
)[0]
if (
    stop_region.count("let shutdown_deadline = tokio::time::Instant::now() + Duration::from_secs(5);") != 1
    or stop_region.count("tokio::time::timeout_at(shutdown_deadline") != 3
):
    raise SystemExit("relay_recreation_source_guard[bounded-teardown]")
cleanup_prefix = stop_region.split("let evidence = RelayTeardownEvidenceV1", 1)[0]
if "return Err(" in cleanup_prefix or cleanup_prefix.count(".drain()).await") != 2:
    raise SystemExit("relay_recreation_source_guard[best-effort-cleanup]")
readiness_region = library.split("async fn await_relay_subject_sets(", 1)[1].split(
    "type RelayPrivateReleaseControlV1", 1
)[0]
if (
    readiness_region.count("tokio::time::sleep(Duration::from_millis(10)).await;") != 2
    or readiness_region.count("async fn await_relay_identities_absent(") != 1
):
    raise SystemExit("relay_recreation_source_guard[bounded-poll-pacing]")
startup_region = library.split("async fn start_selective_with_private_release(", 1)[1].split(
    "async fn stop_and_confirm(mut self)", 1
)[0]
startup_markers = (
    "let mut public_subscriptions = Vec::new();",
    "let mut private_subscriptions = Vec::new();",
    "let mut tasks = Vec::new();",
)
if any(startup_region.count(marker) != 1 for marker in startup_markers):
    raise SystemExit("relay_recreation_source_guard[startup-inventory]")
if not (
    startup_region.index(startup_markers[0])
    < startup_region.index(startup_markers[1])
    < startup_region.index("private_client\n                .flush()")
    < startup_region.index(startup_markers[2])
):
    raise SystemExit("relay_recreation_source_guard[startup-spawn-order]")
if (
    library.count("fn exact_public_relay_subjects() -> BTreeSet<String>") != 1
    or library.count("fn exact_private_relay_subjects() -> BTreeSet<String>") != 1
    or len(exact_public_subjects) != 9
    or len(exact_private_subjects) != 3
):
    raise SystemExit("relay_recreation_source_guard[exact-subject-cardinality]")
if ".stop();" in library:
    raise SystemExit("relay_recreation_source_guard[abort-only-stop]")
if "RuntimeRequestObservationV1::Other,\n                        RuntimeWitnessClientErrorV1::Unavailable" in library:
    raise SystemExit("relay_recreation_source_guard[other-unavailable]")
normalized = "".join(library.split())
if (
    library.count("if self.tasks.len() != 12") != 1
    or library.count("let task_inventory_valid = self.tasks.len() == 12;") != 1
    or library.count("WitnessServiceOperationV1::") < 9
    or library.count("LiveRelayLegsV1::start_after_private_release(") != 2
    or normalized.count(".stop_and_confirm().await") != 4
):
    raise SystemExit("relay_recreation_source_guard[cardinality]")
reason_counts = {
    '"delayed_readiness_completed_early"': 2,
    '"relay_identity_reuse_accepted"': 1,
    '"public_subscription_set"': 2,
    '"private_subscription_set"': 2,
}
for reason, expected in reason_counts.items():
    if library.count(reason) != expected:
        raise SystemExit(f"relay_recreation_source_guard[reason:{reason}:{library.count(reason)}]")
process_tail = conformance.rsplit("def run_bounded_process_group(", 1)
if len(process_tail) != 2:
    raise SystemExit("relay_recreation_source_guard[process-group-helper]")
process_helper = process_tail[1].split("await_anchor = '''", 1)[0]
process_fragments = (
    "start_new_session=True",
    "except subprocess.TimeoutExpired as timeout_error:",
    "os.killpg(process.pid, signal.SIGTERM)",
    "os.killpg(process.pid, signal.SIGKILL)",
    'raise SystemExit("relay_recreation_mutant[process-group-reap]")',
)
if any(process_helper.count(fragment) != 1 for fragment in process_fragments):
    raise SystemExit("relay_recreation_source_guard[process-group-helper]")
if process_tail[1].count("run_bounded_process_group(") != 2:
    raise SystemExit("relay_recreation_source_guard[process-group-callers]")
for name, old in (
    ("session", "start_new_session=True"),
    ("killpg", "os.killpg(process.pid, signal.SIGKILL)"),
):
    candidate = process_helper.replace(old, "", 1)
    if all(candidate.count(fragment) == 1 for fragment in process_fragments):
        raise SystemExit(f"relay_recreation_source_guard[process-group-survived:{name}]")
print("relay_recreation_process_group_mutations session=1 killpg=1 passed=1")
print("relay_recreation_source_guard tasks=12 drains=2 old_absence=2 public=9 private=3 typed_outcomes=3 passed=1")
PY
}

validate_relay_recreation_mutation_ledger() {
  local ledger="$1" receipts="$2"
  python3 -I - "$ledger" "$receipts" <<'PY'
import hashlib, json, os, pathlib, re, stat, sys
ledger, receipts = map(pathlib.Path, sys.argv[1:])
expected = {
    "abort_only_stop": "old_relay_identity_present",
    "omit_task_await": "relay_task_join_cardinality",
    "omit_public_drain": "old_public_relay_identity_present",
    "omit_private_drain": "old_private_relay_identity_present",
    "accept_old_id": "relay_identity_reuse_accepted",
    "delete_public_set_equality": "public_subscription_set",
    "delete_private_set_equality": "private_subscription_set",
    "zero_duration_fixed_sleep": "delayed_readiness_completed_early",
    "collapse_no_responders_to_other": "no_responders_kind",
    "collapse_other_to_no_responders": "other_kind",
    "accept_no_responders_as_replay": "no_responders_accepted_as_replay",
    "accept_other_as_replay": "other_accepted_as_replay",
}

row_keys = {
    "name", "reason", "source", "source_sha256", "target", "executable",
    "executable_sha256", "runner_receipt", "transcript", "running", "passed",
    "failed", "ignored", "filtered", "vacuous", "target_device", "target_inode",
}
def bounded_regular(path, maximum, expected_mode=None):
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode) or not 1 <= info.st_size <= maximum:
        raise SystemExit(f"relay_recreation_ledger[artifact:{path}]")
    if expected_mode is not None and stat.S_IMODE(info.st_mode) != expected_mode:
        raise SystemExit(f"relay_recreation_ledger[artifact-mode:{path}]")
    before = (info.st_dev, info.st_ino, info.st_mode, info.st_size)
    raw = path.read_bytes()
    after_info = path.lstat()
    after = (after_info.st_dev, after_info.st_ino, after_info.st_mode, after_info.st_size)
    if before != after or len(raw) != info.st_size:
        raise SystemExit(f"relay_recreation_ledger[identity:{path}]")
    return raw
if stat.S_IMODE(ledger.lstat().st_mode) != 0o600:
    raise SystemExit("relay_recreation_ledger[mode]")
raw = bounded_regular(ledger, 65536)
value = json.loads(raw)
if raw != json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n":
    raise SystemExit("relay_recreation_ledger[canonical]")
if set(value) != {"schema_version", "rows"} or value["schema_version"] != 1:
    raise SystemExit("relay_recreation_ledger[schema]")
rows = value["rows"]
if len(rows) != 12 or {row.get("name") for row in rows} != set(expected):
    raise SystemExit("relay_recreation_ledger[inventory]")
receipts_info = receipts.lstat()
if stat.S_ISLNK(receipts_info.st_mode) or not stat.S_ISDIR(receipts_info.st_mode):
    raise SystemExit("relay_recreation_ledger[receipt-root]")
receipts_real = receipts.resolve(strict=True)
source_hashes, executable_hashes, targets, target_identities, filtered_values = set(), set(), set(), set(), set()
fqn = "service_checkpoint_relay_tests::complete_receipt_authority_and_grants_are_observed"
expected_argv = ["--test-threads=1", "--ignored", fqn, "--exact"]
for row in rows:
    if set(row) != row_keys or row["reason"] != expected[row["name"]]:
        raise SystemExit("relay_recreation_ledger[row-schema]")
    if [row[key] for key in ("running", "passed", "failed", "ignored", "vacuous")] != [1, 0, 1, 0, 0]:
        raise SystemExit("relay_recreation_ledger[row-result]")
    paths = {key: pathlib.Path(row[key]) for key in ("source", "target", "executable", "runner_receipt", "transcript")}
    target = paths.pop("target")
    if not target.is_absolute():
        raise SystemExit("relay_recreation_ledger[target-path]")
    target_parent = target.parent.resolve(strict=True)
    if os.path.commonpath([str(receipts_real), str(target_parent)]) != str(receipts_real):
        raise SystemExit("relay_recreation_ledger[target-path-escape]")
    target_info = target.lstat()
    if stat.S_ISLNK(target_info.st_mode) or not stat.S_ISDIR(target_info.st_mode) or stat.S_IMODE(target_info.st_mode) != 0o700:
        raise SystemExit("relay_recreation_ledger[target-type]")
    target_resolved = target.resolve(strict=True)
    if str(target_resolved) != row["target"]:
        raise SystemExit("relay_recreation_ledger[target-canonical-path]")
    if os.path.commonpath([str(receipts_real), str(target_resolved)]) != str(receipts_real):
        raise SystemExit("relay_recreation_ledger[target-path-escape]")
    if list(target.iterdir()):
        raise SystemExit("relay_recreation_ledger[target-content-retained]")
    if (target_info.st_dev, target_info.st_ino) != (row["target_device"], row["target_inode"]):
        raise SystemExit("relay_recreation_ledger[target-identity]")
    resolved = {key: path.resolve(strict=True) for key, path in paths.items()}
    if any(str(resolved[key]) != row[key] for key in resolved):
        raise SystemExit("relay_recreation_ledger[canonical-path]")
    if any(os.path.commonpath([str(receipts_real), str(path)]) != str(receipts_real) for path in resolved.values()):
        raise SystemExit("relay_recreation_ledger[path-escape]")
    source_raw = bounded_regular(resolved["source"], 2 * 1024 * 1024, 0o600)
    executable_raw = bounded_regular(resolved["executable"], 512 * 1024 * 1024, 0o500)
    runner_raw = bounded_regular(resolved["runner_receipt"], 4096, 0o600)
    transcript_raw = bounded_regular(resolved["transcript"], 16 * 1024 * 1024, 0o600)
    source_digest = hashlib.sha256(source_raw).hexdigest()
    executable_digest = hashlib.sha256(executable_raw).hexdigest()
    if source_digest != row["source_sha256"] or executable_digest != row["executable_sha256"]:
        raise SystemExit("relay_recreation_ledger[digest]")
    runner = json.loads(runner_raw)
    if runner_raw != json.dumps(runner, sort_keys=True, separators=(",", ":")).encode() + b"\n":
        raise SystemExit("relay_recreation_ledger[runner-canonical]")
    if runner != {"argv": expected_argv, "executable": row["executable"], "sha256": executable_digest}:
        raise SystemExit("relay_recreation_ledger[runner-identity]")
    transcript = transcript_raw.decode("utf-8")
    summary = re.findall(r"test result: FAILED\. 0 passed; 1 failed; 0 ignored; 0 measured; ([0-9]+) filtered out", transcript)
    if transcript.count("running 1 test") != 1 or transcript.count(f"test {fqn} ... FAILED") != 1 or len(summary) != 1:
        raise SystemExit("relay_recreation_ledger[transcript-cardinality]")
    if expected[row["name"]] not in transcript or int(summary[0]) != row["filtered"]:
        raise SystemExit("relay_recreation_ledger[late-relation]")
    source_hashes.add(source_digest); executable_hashes.add(executable_digest); targets.add(row["target"]); target_identities.add((row["target_device"], row["target_inode"])); filtered_values.add(row["filtered"])
if len(source_hashes) != 12 or len(executable_hashes) != 12 or len(targets) != 12 or len(target_identities) != 12 or len(filtered_values) != 1:
    raise SystemExit("relay_recreation_ledger[uniqueness]")
print("relay_recreation_mutation_ledger rows=12 source_hashes=12 sealed_executable_hashes=12 targets_pruned=12 empty_target_dirs=12 target_identities=12 argv_receipts=12 transcripts=12 passed=1")
PY
}

relay_recreation_target_cleanup_control() {
  local ledger="$1" receipts="$2" target retained output status=0
  target="$(python3 -I - "$ledger" "$receipts" <<'PY'
import json, os, pathlib, sys
ledger, receipts = map(pathlib.Path, sys.argv[1:])
receipts = receipts.resolve(strict=True)
value = json.loads(ledger.read_bytes())
target = pathlib.Path(value["rows"][0]["target"])
resolved = target.resolve(strict=True)
if target.is_symlink() or not target.is_dir() or list(target.iterdir()) or os.path.commonpath([str(receipts), str(resolved)]) != str(receipts):
    raise SystemExit("relay_recreation_cleanup_control[target]")
print(target)
PY
)"
  retained="$target/retained-build-artifact"
  (umask 077; touch -- "$retained")
  output="$(validate_relay_recreation_mutation_ledger "$ledger" "$receipts" 2>&1)" || status=$?
  rm -f -- "$retained"
  if [ "$status" -eq 0 ] || [[ "$output" != *'relay_recreation_ledger[target-content-retained]'* ]]; then
    echo "relay_recreation_cleanup_control[unexpected:$status:$output]" >&2
    return 1
  fi
  validate_relay_recreation_mutation_ledger "$ledger" "$receipts"
  echo "relay_recreation_target_cleanup_mutation retained_build_child_killed=1 targets_pruned=12 empty_target_dirs=12 passed=1"
}

run_relay_recreation_mutants() {
  local ledger="${PHASE285_RELAY_RECREATION_LEDGER:-}"
  local receipts="${PHASE285_RELAY_RECREATION_RECEIPT_ROOT:-}"
  local scratch
  scratch="$(phase285_create_confined_scratch phase285-relay-recreation-mutants)"
  PHASE285_WITNESS_TEMP_DIR="$scratch"
  trap cleanup_temp_dir_on_exit EXIT
  if [ "${PHASE285_RELAY_RECREATION_SOURCE_ONLY:-0}" = 1 ]; then
    ledger="$scratch/source-only-ledger.json"
    receipts="$scratch/source-only-receipts"
  else
    [ -n "$ledger" ] || { echo "PHASE285_RELAY_RECREATION_LEDGER required" >&2; return 2; }
    [ -n "$receipts" ] || { echo "PHASE285_RELAY_RECREATION_RECEIPT_ROOT required" >&2; return 2; }
  fi
  relay_recreation_source_guard
  python3 -I - "$ROOT_DIR" "$scratch" "$ledger" "$receipts" <<'PY'
import hashlib, json, os, pathlib, re, shutil, signal, stat, subprocess, sys, time

root, scratch, ledger, receipts = map(pathlib.Path, sys.argv[1:])
root = root.resolve(strict=True)
scratch = scratch.resolve(strict=True)
if not ledger.is_absolute() or not receipts.is_absolute() or ledger.exists() or receipts.exists():
    raise SystemExit("relay_recreation_mutant[output-freshness]")
for parent in (ledger.parent, receipts.parent):
    info = parent.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise SystemExit("relay_recreation_mutant[output-parent]")
os.mkdir(receipts, 0o700)
exact = scratch / "source"
exact.mkdir(mode=0o700)

def reject_cargo_ancestor_configuration(subject):
    current = subject.resolve(strict=True)
    while True:
        for relative in (pathlib.Path(".cargo/config"), pathlib.Path(".cargo/config.toml")):
            if os.path.lexists(current / relative):
                raise SystemExit("relay_recreation_mutant[cargo-ancestor-config]")
        if current.parent == current:
            break
        current = current.parent

reject_cargo_ancestor_configuration(exact)
tracked = subprocess.run(
    ["git", "ls-files", "-z"], cwd=root, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True
).stdout.split(b"\0")
for raw in tracked:
    if not raw:
        continue
    relative = pathlib.Path(os.fsdecode(raw))
    source, destination = root / relative, exact / relative
    destination.parent.mkdir(parents=True, exist_ok=True)
    if source.is_symlink():
        destination.symlink_to(os.readlink(source))
    elif source.is_file():
        shutil.copy2(source, destination)
    else:
        raise SystemExit(f"relay_recreation_mutant[tracked-type:{relative}]")
reject_cargo_ancestor_configuration(exact)

lib_path = exact / "crates/swarm-governance-witness/src/lib.rs"
runtime_path = exact / "crates/swarm-governance-witness/src/runtime_client.rs"
original_lib = lib_path.read_text(encoding="utf-8")
original_runtime = runtime_path.read_text(encoding="utf-8")

def replace_once(text, old, new, label):
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"relay_recreation_mutant[{label}:anchor:{count}]")
    return text.replace(old, new, 1)

def lib_mutation(label, old, new):
    return (label, "lib.rs", replace_once(original_lib, old, new, label), original_runtime)

def lib_mutation_many(label, replacements):
    source = original_lib
    for old, new in replacements:
        source = replace_once(source, old, new, label)
    return (label, "lib.rs", source, original_runtime)

def runtime_mutation(label, old, new):
    return (label, "runtime_client.rs", original_lib, replace_once(original_runtime, old, new, label))

def run_bounded_process_group(argv, *, cwd, env, timeout):
    process = subprocess.Popen(
        argv,
        cwd=cwd,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        start_new_session=True,
    )
    try:
        output, _ = process.communicate(timeout=timeout)
        return subprocess.CompletedProcess(argv, process.returncode, output)
    except subprocess.TimeoutExpired as timeout_error:
        partial = timeout_error.output or ""
        if isinstance(partial, bytes):
            partial = partial.decode(errors="replace")
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            output, _ = process.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            try:
                output, _ = process.communicate(timeout=5)
            except subprocess.TimeoutExpired as error:
                raise SystemExit("relay_recreation_mutant[process-group-reap]") from error
        return subprocess.CompletedProcess(
            argv,
            124,
            partial + (output or "") + "\nrelay_recreation_process_group_timeout reaped=1\n",
        )

await_anchor = '''            let shutdown_deadline = tokio::time::Instant::now() + Duration::from_secs(5);
            let mut tasks_joined = 0_usize;
            let mut task_joins_valid = true;
            while let Some(mut task) = self.tasks.pop() {'''
await_mutant = '''            let shutdown_deadline = tokio::time::Instant::now() + Duration::from_secs(5);
            let mut tasks_joined = 0_usize;
            let mut task_joins_valid = true;
            drop(self.tasks.pop());
            while let Some(mut task) = self.tasks.pop() {'''
public_drain_anchor = '''            let public_client_drained = matches!(
                tokio::time::timeout_at(shutdown_deadline, self.public_client.drain()).await,
                Ok(Ok(()))
            );
            if public_client_drained {
                clients_drained += 1;
            }'''
private_drain_anchor = '''            let private_client_drained = matches!(
                tokio::time::timeout_at(shutdown_deadline, self.private_client.drain()).await,
                Ok(Ok(()))
            );
            if private_client_drained {
                clients_drained += 1;
            }'''
task_count_validation = '''                && tasks_joined == 12'''
drain_count_validation = '''                && clients_drained == 2'''
identity_anchor = '''                || [self.public_client_id, self.private_client_id]
                    .into_iter()
                    .any(|current| {
                        current == old_public_client_id || current == old_private_client_id
                    })'''
mutations = [
    lib_mutation(
        "abort_only_stop",
        "                first_legs.stop_and_confirm().await,",
        "                first_legs.abort_only_for_control().await,",
    ),
    lib_mutation_many(
        "omit_task_await",
        ((await_anchor, await_mutant), (task_count_validation, "                && tasks_joined <= 12")),
    ),
    lib_mutation_many(
        "omit_public_drain",
        ((public_drain_anchor, "            let public_client_drained = { drop(self.public_client); false };"),
         (drain_count_validation, "                && clients_drained >= 1")),
    ),
    lib_mutation_many(
        "omit_private_drain",
        ((private_drain_anchor, "            let private_client_drained = { drop(self.private_client); false };"),
         (drain_count_validation, "                && clients_drained >= 1")),
    ),
    lib_mutation("accept_old_id", identity_anchor, "                || false"),
    lib_mutation(
        "delete_public_set_equality",
        "        public_subjects == expected_public && private_subjects == expected_private",
        "        private_subjects == expected_private",
    ),
    lib_mutation(
        "delete_private_set_equality",
        "        public_subjects == expected_public && private_subjects == expected_private",
        "        public_subjects == expected_public",
    ),
    lib_mutation(
        "zero_duration_fixed_sleep",
        "            let replay_start = tokio::spawn(LiveRelayLegsV1::start_after_private_release(",
        "            let replay_start = tokio::spawn(LiveRelayLegsV1::start_with_zero_sleep_control(",
    ),
    runtime_mutation(
        "collapse_no_responders_to_other",
        "            async_nats::RequestErrorKind::NoResponders => Self::NoResponders,",
        "            async_nats::RequestErrorKind::NoResponders => Self::Other,",
    ),
    runtime_mutation(
        "collapse_other_to_no_responders",
        "            async_nats::RequestErrorKind::Other => Self::Other,",
        "            async_nats::RequestErrorKind::Other => Self::NoResponders,",
    ),
    runtime_mutation(
        "accept_no_responders_as_replay",
        "        matches!(self, Self::Response)",
        "        matches!(self, Self::Response | Self::NoResponders)",
    ),
    runtime_mutation(
        "accept_other_as_replay",
        "        matches!(self, Self::Response)",
        "        matches!(self, Self::Response | Self::Other)",
    ),
]
reasons = {
    "abort_only_stop": "old_relay_identity_present",
    "omit_task_await": "relay_task_join_cardinality",
    "omit_public_drain": "old_public_relay_identity_present",
    "omit_private_drain": "old_private_relay_identity_present",
    "accept_old_id": "relay_identity_reuse_accepted",
    "delete_public_set_equality": "public_subscription_set",
    "delete_private_set_equality": "private_subscription_set",
    "zero_duration_fixed_sleep": "delayed_readiness_completed_early",
    "collapse_no_responders_to_other": "no_responders_kind",
    "collapse_other_to_no_responders": "other_kind",
    "accept_no_responders_as_replay": "no_responders_accepted_as_replay",
    "accept_other_as_replay": "other_accepted_as_replay",
}
if len(mutations) != 12 or {item[0] for item in mutations} != set(reasons):
    raise SystemExit("relay_recreation_mutant[inventory]")
if os.environ.get("PHASE285_RELAY_RECREATION_SOURCE_ONLY") == "1":
    digests = []
    for name, source_name, lib_source, runtime_source in mutations:
        source = lib_source if source_name == "lib.rs" else runtime_source
        digest = hashlib.sha256(source.encode()).hexdigest()
        if digest in digests:
            raise SystemExit(f"relay_recreation_mutant[{name}:source-reuse]")
        digests.append(digest)
    hostile_cargo = scratch / ".cargo"
    hostile_cargo.mkdir(mode=0o700)
    hostile_config = hostile_cargo / "config.toml"
    hostile_config.write_text("[build]\nrustflags = ['--phase285-mutant']\n", encoding="utf-8")
    try:
        reject_cargo_ancestor_configuration(exact)
    except SystemExit as error:
        if str(error) != "relay_recreation_mutant[cargo-ancestor-config]":
            raise
    else:
        raise SystemExit("relay_recreation_mutant[cargo-ancestor-config-survived]")
    hostile_config.unlink()
    hostile_cargo.rmdir()
    reject_cargo_ancestor_configuration(exact)
    receipts.rmdir()
    print("relay_recreation_mutation_sources inventory=12 unique=12 lib=8 runtime=4 hostile_ancestor_config=1 passed=1")
    raise SystemExit(0)
curl_value = os.environ.get("PHASE285_CONNZ_CURL_BIN", "")
curl_bin = pathlib.Path(curl_value)
try:
    curl_info = curl_bin.lstat()
    curl_resolved = curl_bin.resolve(strict=True)
except (FileNotFoundError, OSError, RuntimeError):
    raise SystemExit("relay_recreation_mutant[connz-curl-binding]")
if (
    not curl_bin.is_absolute()
    or curl_bin.is_symlink()
    or not stat.S_ISREG(curl_info.st_mode)
    or stat.S_IMODE(curl_info.st_mode) & 0o111 == 0
    or curl_resolved != curl_bin
):
    raise SystemExit("relay_recreation_mutant[connz-curl-binding]")
source_hashes, executable_hashes, targets, rows = set(), set(), set(), []
fqn = "service_checkpoint_relay_tests::complete_receipt_authority_and_grants_are_observed"
for ordinal, (name, source_name, lib_source, runtime_source) in enumerate(mutations, 1):
    lib_path.write_text(lib_source, encoding="utf-8")
    runtime_path.write_text(runtime_source, encoding="utf-8")
    artifact_root = receipts / f"{ordinal:02d}-{name}"
    artifact_root.mkdir(mode=0o700)
    target = artifact_root / "target"
    if target.exists() or target.is_symlink():
        raise SystemExit(f"relay_recreation_mutant[{name}:target-preexisting]")
    source_receipt = artifact_root / source_name
    source_bytes = (lib_source if source_name == "lib.rs" else runtime_source).encode()
    fd = os.open(source_receipt, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as output:
        output.write(source_bytes); output.flush(); os.fsync(output.fileno())
    source_digest = hashlib.sha256(source_bytes).hexdigest()
    if source_digest in source_hashes:
        raise SystemExit(f"relay_recreation_mutant[{name}:source-reuse]")
    source_hashes.add(source_digest)
    env = os.environ.copy()
    env.update({"CARGO_TARGET_DIR": str(target), "CARGO_INCREMENTAL": "0", "CARGO_NET_OFFLINE": "true"})
    print(f"relay_recreation_mutation_progress name={name} phase=compile ordinal={ordinal}/12", flush=True)
    compile_result = run_bounded_process_group(
        ["cargo", "test", "-p", "swarm-governance-witness", "--lib", "--locked", "--offline", "--no-run", "--message-format=json-render-diagnostics"],
        cwd=exact, env=env, timeout=600,
    )
    if compile_result.returncode != 0:
        raise SystemExit(f"relay_recreation_mutant[{name}:compile]\n{compile_result.stdout}")
    artifacts, finished = [], []
    for line in compile_result.stdout.splitlines():
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if value.get("reason") == "build-finished":
            finished.append(value.get("success"))
        if value.get("reason") != "compiler-artifact":
            continue
        item, profile, executable = value.get("target", {}), value.get("profile", {}), value.get("executable")
        if item.get("name") == "swarm_governance_witness" and item.get("kind") == ["lib"] and profile.get("test") is True and executable:
            artifacts.append(pathlib.Path(executable))
    if finished != [True] or len(artifacts) != 1:
        raise SystemExit(f"relay_recreation_mutant[{name}:compile-receipt]")
    raw_compiled_executable = artifacts[0]
    raw_executable_info = raw_compiled_executable.lstat()
    if stat.S_ISLNK(raw_executable_info.st_mode) or not stat.S_ISREG(raw_executable_info.st_mode):
        raise SystemExit(f"relay_recreation_mutant[{name}:executable-type]")
    compiled_executable = raw_compiled_executable.resolve(strict=True)
    target_real = target.resolve(strict=True)
    if compiled_executable.is_symlink() or os.path.commonpath([str(target_real), str(compiled_executable)]) != str(target_real):
        raise SystemExit(f"relay_recreation_mutant[{name}:executable-path]")
    target.chmod(0o700)
    target_info = target.lstat()
    if stat.S_ISLNK(target_info.st_mode) or not stat.S_ISDIR(target_info.st_mode) or stat.S_IMODE(target_info.st_mode) != 0o700:
        raise SystemExit(f"relay_recreation_mutant[{name}:target-type]")
    target_identity = (target_info.st_dev, target_info.st_ino)
    executable = artifact_root / "sealed-test-executable"
    source_info = compiled_executable.lstat()
    if not stat.S_ISREG(source_info.st_mode) or source_info.st_size <= 0 or source_info.st_size > 512 * 1024 * 1024:
        raise SystemExit(f"relay_recreation_mutant[{name}:executable-size]")
    compiled_executable_hasher = hashlib.sha256()
    sealed_executable_hasher = hashlib.sha256()
    fd = os.open(executable, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o500)
    with compiled_executable.open("rb") as source_handle, os.fdopen(fd, "wb") as sealed_handle:
        while True:
            chunk = source_handle.read(1024 * 1024)
            if not chunk:
                break
            compiled_executable_hasher.update(chunk); sealed_executable_hasher.update(chunk); sealed_handle.write(chunk)
        sealed_handle.flush(); os.fsync(sealed_handle.fileno()); os.fchmod(sealed_handle.fileno(), 0o500)
    executable = executable.resolve(strict=True)
    executable_digest = sealed_executable_hasher.hexdigest()
    if executable_digest != compiled_executable_hasher.hexdigest() or executable.lstat().st_size != source_info.st_size:
        raise SystemExit(f"relay_recreation_mutant[{name}:sealed-executable]")
    if executable_digest in executable_hashes:
        raise SystemExit(f"relay_recreation_mutant[{name}:executable-reuse]")
    executable_hashes.add(executable_digest)
    argv = ["--test-threads=1", "--ignored", fqn, "--exact"]
    runner_receipt = artifact_root / "runner.json"
    runner_value = {"argv": argv, "executable": str(executable), "sha256": executable_digest}
    runner_bytes = json.dumps(runner_value, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    fd = os.open(runner_receipt, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as output:
        output.write(runner_bytes); output.flush(); os.fsync(output.fileno())
    print(f"relay_recreation_mutation_progress name={name} phase=execute ordinal={ordinal}/12", flush=True)
    result = run_bounded_process_group(
        [str(executable), *argv], cwd=exact, env=env, timeout=180,
    )
    transcript = artifact_root / "transcript.txt"
    fd = os.open(transcript, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as output:
        output.write(result.stdout); output.flush(); os.fsync(output.fileno())
    summary = re.findall(r"test result: FAILED\. 0 passed; 1 failed; 0 ignored; 0 measured; ([0-9]+) filtered out", result.stdout)
    reason = reasons[name]
    if result.returncode == 0 or result.stdout.count("running 1 test") != 1 or len(summary) != 1 or reason not in result.stdout:
        raise SystemExit(f"relay_recreation_mutant[{name}:wrong-reason]\n{result.stdout}")
    final_target_info = target_real.lstat()
    if (
        stat.S_ISLNK(final_target_info.st_mode)
        or not stat.S_ISDIR(final_target_info.st_mode)
        or (final_target_info.st_dev, final_target_info.st_ino) != target_identity
    ):
        raise SystemExit(f"relay_recreation_mutant[{name}:target-identity]")
    for child in list(target_real.iterdir()):
        child_info = child.lstat()
        if stat.S_ISLNK(child_info.st_mode) or stat.S_ISREG(child_info.st_mode):
            child.unlink()
        elif stat.S_ISDIR(child_info.st_mode):
            shutil.rmtree(child)
        else:
            raise SystemExit(f"relay_recreation_mutant[{name}:target-child-type]")
    final_target_info = target_real.lstat()
    if (
        list(target_real.iterdir())
        or (final_target_info.st_dev, final_target_info.st_ino) != target_identity
        or stat.S_IMODE(final_target_info.st_mode) != 0o700
    ):
        raise SystemExit(f"relay_recreation_mutant[{name}:target-prune]")
    targets.add(str(target_real))
    rows.append({
        "name": name, "reason": reason, "source": str(source_receipt.resolve(strict=True)), "source_sha256": source_digest,
        "target": str(target_real), "executable": str(executable), "executable_sha256": executable_digest,
        "runner_receipt": str(runner_receipt.resolve(strict=True)), "transcript": str(transcript.resolve(strict=True)),
        "target_device": target_identity[0], "target_inode": target_identity[1],
        "running": 1, "passed": 0, "failed": 1, "ignored": 0, "filtered": int(summary[0]), "vacuous": 0,
    })
    print(f"relay_recreation_mutation name={name} reason={reason} compiled=1 executed=1 killed=1 vacuous=0", flush=True)
lib_path.write_text(original_lib, encoding="utf-8")
runtime_path.write_text(original_runtime, encoding="utf-8")
if len(source_hashes) != 12 or len(executable_hashes) != 12 or len(targets) != 12:
    raise SystemExit("relay_recreation_mutant[identity-cardinality]")
payload = json.dumps({"schema_version": 1, "rows": rows}, sort_keys=True, separators=(",", ":")).encode() + b"\n"
fd = os.open(ledger, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(fd, "wb") as output:
    output.write(payload); output.flush(); os.fsync(output.fileno())
print("relay_recreation_mutations inventory=12 executed=12 killed=12 vacuous=0 distinct_targets=12 source_receipts=12 executable_receipts=12 argv_receipts=12 passed=1")
PY
  if [ "${PHASE285_RELAY_RECREATION_SOURCE_ONLY:-0}" != 1 ]; then
    validate_relay_recreation_mutation_ledger "$ledger" "$receipts"
    relay_recreation_target_cleanup_control "$ledger" "$receipts"
  fi
  cleanup_temp_dir
  trap - EXIT
}

run_relay_recreation_mutants_for_ci() {
  local parent="${PHASE285_CI_ROUTE_TEMP_PARENT:?PHASE285_CI_ROUTE_TEMP_PARENT required}"
  local reservation ledger receipts
  reservation="$(mktemp "$parent/relay-recreation.XXXXXX")"
  ledger="$reservation.ledger.json"
  receipts="$reservation.receipts"
  rm -f -- "$reservation"
  [ ! -e "$ledger" ] && [ ! -e "$receipts" ] || {
    echo "relay recreation CI artifacts are not fresh" >&2
    return 1
  }
  PHASE285_RELAY_RECREATION_LEDGER="$ledger" \
  PHASE285_RELAY_RECREATION_RECEIPT_ROOT="$receipts" \
    run_relay_recreation_mutants
  python3 -I - "$parent" "$ledger" "$receipts" <<'PY'
import os, pathlib, shutil, stat, sys
parent, ledger, receipts = map(pathlib.Path, sys.argv[1:])
parent = parent.resolve(strict=True)
for path in (ledger, receipts):
    resolved = path.resolve(strict=True)
    if os.path.commonpath([str(parent), str(resolved)]) != str(parent):
        raise SystemExit("relay_recreation_ci_cleanup[path-escape]")
ledger_info = ledger.lstat()
receipts_info = receipts.lstat()
if stat.S_ISLNK(ledger_info.st_mode) or not stat.S_ISREG(ledger_info.st_mode):
    raise SystemExit("relay_recreation_ci_cleanup[ledger-type]")
if stat.S_ISLNK(receipts_info.st_mode) or not stat.S_ISDIR(receipts_info.st_mode):
    raise SystemExit("relay_recreation_ci_cleanup[receipts-type]")
ledger.unlink()
shutil.rmtree(receipts)
if ledger.exists() or receipts.exists():
    raise SystemExit("relay_recreation_ci_cleanup[residue]")
print("relay_recreation_ci_cleanup ledger=1 receipts=12 residue=0 passed=1")
PY
}

run_service_checkpoint_relay_positive_focus() {
  local accepted_tree="${PHASE285_SERVICE_CHECKPOINT_TREE:?PHASE285_SERVICE_CHECKPOINT_TREE required}"
  local scratch grant_ledger relay_ledger output list_output
  [[ "$accepted_tree" =~ ^[0-9a-f]{40}$ ]] || { echo "service checkpoint relay tree is malformed" >&2; return 1; }
  [[ "${PHASE285_RELAY_TOPOLOGY_TOKEN:-}" == relay-phase285-* ]] || { echo "service checkpoint relay token is absent" >&2; return 1; }
  scratch="$(phase285_create_confined_scratch phase285-relay-positive)"
  PHASE285_WITNESS_TEMP_DIR="$scratch"
  trap cleanup_temp_dir_on_exit EXIT
  grant_ledger="$scratch/grants.json"
  relay_ledger="$scratch/relay.json"
  output="$scratch/relay.txt"
  list_output="$scratch/relay-list.txt"
  relay_recreation_source_guard
  cargo test -p swarm-governance-witness --lib --locked --offline -- --list >"$list_output"
  PHASE285_GRANT_LEDGER="$grant_ledger" PHASE285_RELAY_LEDGER="$relay_ledger" \
  PHASE285_SERVICE_CHECKPOINT_TREE="$accepted_tree" \
    cargo test -p swarm-governance-witness --lib --locked --offline -- --test-threads=1 --ignored \
      service_checkpoint_relay_tests::complete_receipt_authority_and_grants_are_observed --exact | tee "$output"
  validate_service_checkpoint_exact_test "$output" "$list_output" \
    service_checkpoint_relay_tests::complete_receipt_authority_and_grants_are_observed \
    'test service_checkpoint_relay_tests::complete_receipt_authority_and_grants_are_observed ... ok'
  validate_service_checkpoint_grant_ledger "$grant_ledger" "$accepted_tree" relay
  python3 -I - "$relay_ledger" "$accepted_tree" "$PHASE285_RELAY_TOPOLOGY_TOKEN" <<'PY'
import hashlib, json, pathlib, sys
path, tree, token = pathlib.Path(sys.argv[1]), sys.argv[2], sys.argv[3]
raw = path.read_bytes()
def reject(value): raise ValueError(value)
def canonical(value): return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
if not raw.endswith(b"\n") or raw.count(b"\n") != 1: raise SystemExit("relay_positive[framing]")
value = json.loads(raw[:-1], parse_constant=reject)
if canonical(value) + b"\n" != raw: raise SystemExit("relay_positive[canonical]")
if value.get("schema_version") != 1 or value.get("tree") != tree or value.get("invocation_token") != token or value.get("case") != "service_checkpoint_relay_positive" or value.get("operation") != "ReadHead": raise SystemExit("relay_positive[identity]")
for prefix in ("request", "response", "complete_receipt"):
    encoded = bytes.fromhex(value.get(prefix + "_canonical_hex", ""))
    if hashlib.sha256(encoded).hexdigest() != value.get(prefix + "_sha256"): raise SystemExit("relay_positive[" + prefix + "-digest]")
if value.get("post_accept_other_outcome_unknown") is not True or value.get("no_responders_unavailable") is not True or value.get("replay_forwarded") is not True or not 0 < value.get("first_request_started_at_micros", 0) < value.get("replay_request_started_at_micros", 0): raise SystemExit("relay_positive[replay]")
connections = value.get("relay_connections")
ids = value.get("relay_connection_client_ids")
if not isinstance(connections, list) or len(connections) != 4 or not isinstance(ids, list) or len(ids) != 4 or len(set(ids)) != 4: raise SystemExit("relay_positive[connections]")
for connection, client_id in zip(connections, ids):
    if connection.get("server_client_id") != client_id or connection.get("account") != "PHASE285_RELAY" or connection.get("authenticated_user") != "phase285_relay": raise SystemExit("relay_positive[authority]")
    evidence = bytes.fromhex(connection.get("server_evidence_canonical_hex", ""))
    if hashlib.sha256(evidence).hexdigest() != connection.get("server_evidence_sha256"): raise SystemExit("relay_positive[server-evidence]")
print("service_checkpoint_relay_positive public_legs=2 private_legs=2 identities=4 receipt=1 outcome_unknown=1 replay=1 passed=1")
PY
  grep -Fxc 'relay_recreation_errors no_responders=1 no_responders_unavailable=1 post_accept_other=1 post_accept_other_outcome_unknown=1 rejected_as_replay=2 passed=1' "$output" >/dev/null
  grep -Fxc 'relay_recreation_teardown tasks_joined=12 old_absent=2 drained=2 passed=1' "$output" >/dev/null
  grep -Fxc 'relay_recreation_readiness delayed_pending=1 new_present=2 public_subscriptions=9 private_subscriptions=3 wildcard=0 passed=1' "$output" >/dev/null
  grep -Fxc 'relay_replay_request_outcome kind=response passed=1' "$output" >/dev/null
}

ci_harness_target_inventory() {
  local destination="$1" metadata
  metadata="${destination}.metadata.json"
  cargo metadata --locked --offline --no-deps --format-version 1 >"$metadata"
  python3 -I - "$ROOT_DIR" "$metadata" >"$destination" <<'PY'
import json
import os
import pathlib
import stat
import sys

root = pathlib.Path(sys.argv[1]).resolve(strict=True)
data = json.loads(pathlib.Path(sys.argv[2]).read_text())
packages = [package for package in data["packages"] if package["name"] == "swarm-governance-witness"]
if len(packages) != 1:
    raise SystemExit(f"ci_harness_targets[package-cardinality:{len(packages)}]")
rows = []
for target in packages[0]["targets"]:
    kinds = target.get("kind", [])
    if not target.get("test"):
        continue
    if kinds not in (["lib"], ["test"], ["bin"]):
        raise SystemExit(f"ci_harness_targets[unsupported-test-kind:{target.get('name')}:{kinds}]")
    kind = kinds[0]
    name = target["name"]
    source = pathlib.Path(target["src_path"])
    try:
        metadata = source.lstat()
        resolved = source.resolve(strict=True)
        relative = resolved.relative_to(root)
    except (FileNotFoundError, OSError, RuntimeError, ValueError) as error:
        raise SystemExit(f"ci_harness_targets[source-confinement:{name}:{error}]") from error
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise SystemExit(f"ci_harness_targets[source-type:{name}]")
    if resolved != pathlib.Path(os.path.abspath(source)):
        raise SystemExit(f"ci_harness_targets[source-alias:{name}]")
    key = "lib" if kind == "lib" else name if kind == "test" else f"bin:{name}"
    rows.append((key, kind, name, relative.as_posix()))
if sum(kind == "lib" for _, kind, _, _ in rows) != 1:
    raise SystemExit("ci_harness_targets[lib-cardinality]")
if len(rows) != len(set(row[0] for row in rows)) or len(rows) != len(set(row[3] for row in rows)):
    raise SystemExit("ci_harness_targets[duplicate-key-or-source]")
for row in sorted(rows):
    print("\t".join(row))
PY
  rm -f -- "$metadata"
  [ -s "$destination" ] || { echo "compiled test-harness target inventory is empty" >&2; return 1; }
}

ci_harness_compiled_ignored_inventory() {
  local destination="$1" targets ordinary
  targets="${destination}.targets.tsv"
  ordinary="${destination}.ordinary.tsv"
  local target kind name source output all_output
  : >"$destination"
  : >"$ordinary"
  ci_harness_target_inventory "$targets"
  while IFS=$'\t' read -r target kind name source; do
    [ -n "$target" ] || continue
    output="${destination}.${target}"
    if [ "$kind" = lib ]; then
      cargo test -p swarm-governance-witness --lib --locked --offline -- --list --ignored >"$output"
      all_output="${destination}.${target}.all"
      cargo test -p swarm-governance-witness --lib --locked --offline -- --list >"$all_output"
    elif [ "$kind" = test ]; then
      cargo test -p swarm-governance-witness --test "$name" --locked --offline -- --list --ignored >"$output"
    elif [ "$kind" = bin ]; then
      cargo test -p swarm-governance-witness --bin "$name" --locked --offline -- --list --ignored >"$output"
    else
      echo "unknown CI harness target kind: $kind" >&2
      return 1
    fi
    python3 -I - "$target" "$output" >>"$destination" <<'PY'
import re,sys
target,path=sys.argv[1:]
rows=[]
for line in open(path,encoding="utf-8"):
    match=re.fullmatch(r"([^:]+(?:::[^:]+)*): test\n?",line)
    if match: rows.append((target,match.group(1)))
if len(rows)!=len(set(rows)): raise SystemExit(f"ci_harness_compiled_inventory[duplicate:{target}]")
for row in rows: print("\t".join(row))
PY
    if [ "$kind" = lib ]; then
      python3 -I - "$target" "$all_output" "$output" >"$ordinary" <<'PY'
import re,sys
target,all_path,ignored_path=sys.argv[1:]
def names(path):
    rows=[]
    for line in open(path,encoding="utf-8"):
        match=re.fullmatch(r"([^:]+(?:::[^:]+)*): test\n?",line)
        if match: rows.append(match.group(1))
    if len(rows)!=len(set(rows)): raise SystemExit(f"ci_harness_compiled_inventory[duplicate:{target}:{path}]")
    return rows
all_names=names(all_path); ignored=set(names(ignored_path))
for fqn in sorted(set(all_names)-ignored): print(f"{target}\t{fqn}")
PY
    fi
  done <"$targets"
  LC_ALL=C sort -o "$destination" "$destination"
  [ -s "$destination" ] || { echo "compiled ignored inventory is empty" >&2; return 1; }
  [ "$(wc -l <"$destination" | tr -d ' ')" -eq "$(LC_ALL=C sort -u "$destination" | wc -l | tr -d ' ')" ] || {
    echo "compiled ignored inventory contains duplicates" >&2
    return 1
  }
  local pure=$'lib\tdeadline_state_machine_tests::deadline_state_machine_is_receipt_anchored_and_mutation_sensitive'
  if [ "$(grep -Fxc "$pure" "$ordinary")" -ne 1 ] || grep -Fqx "$pure" "$destination"; then
    echo "ci_harness_registration[pure-ordinary-compiled]" >&2
    return 1
  fi
  echo "ci_harness_targets compiled=$(wc -l <"$targets" | tr -d ' ') metadata_derived=1 ordinary_lib=$(wc -l <"$ordinary" | tr -d ' ') passed=1"
}

ci_harness_source_reason_guard() {
  local inventory="$1" targets ordinary
  targets="${inventory}.targets.tsv"
  ordinary="${inventory}.ordinary.tsv"
  python3 -I - "$ROOT_DIR" "$inventory" "$targets" "$ordinary" <<'PY'
import pathlib,re,sys
root=pathlib.Path(sys.argv[1]); inventory=pathlib.Path(sys.argv[2]); targets=pathlib.Path(sys.argv[3]); ordinary=pathlib.Path(sys.argv[4])
rows=[tuple(line.rstrip("\n").split("\t")) for line in inventory.open()]
target_rows=[tuple(line.rstrip("\n").split("\t")) for line in targets.open()]
if any(len(row)!=4 for row in target_rows): raise SystemExit("ci_harness_registration[target-inventory-malformed]")
sources={key:root/source for key,_kind,_name,source in target_rows}
texts={name:path.read_text() for name,path in sources.items()}
seam_anchors={
 "deadline_state_machine_tests::subscriber_callsite_is_receipt_anchored_and_mutation_sensitive":"run_subscriber_callsite()",
 "service_checkpoint_observation_tests::worker_observations_are_real_and_reconciled":"run_worker_observation_test",
 "service_checkpoint_relay_tests::complete_receipt_authority_and_grants_are_observed":"run_complete_receipt_suppression_test",
 "service_checkpoint_transport_semantics_tests::post_command_other_is_distinct_from_pre_send_drain":"run_transport_other_test",
 "service_checkpoint_transport_semantics_tests::public_and_private_expired_response_grants_recover_exactly_once":"run_response_grant_recovery_test",
 "full_service_path_constructor_deadline_is_exact_and_receipt_bound":"connect_harness_role(",
 "full_service_path_rejects_runtime_private_subject_and_store_raw_api":"initialize_harness_store_stream()",
 "full_service_path_rejects_credential_account_and_mount_swaps":"StoreRoleConnectionV1::connect(",
 "full_service_path_validates_proxy_response_before_public_attestation":"initialize_harness_store_stream()",
 "full_service_path_fails_closed_on_store_queue_exhaustion":"Fixture::new(",
 "production_initializer_creates_reopens_and_reproduces_ready":"initialize_store(config.clone())",
 "jetstream_cas_rejects_wrong_revision_header_or_ack":"live_fixture(",
 "jetstream_cas_confirms_raw_sequence_and_bytes":"live_fixture(",
 "jetstream_cas_rejects_del_purge_rollup_and_direct_reads":"live_fixture(",
 "jetstream_checkpoint_survives_restart_for_current_predecessor_prepared_abort_and_genesis":"current_server()",
 "jetstream_checkpoint_rejects_rolled_back_anchor_or_recreated_stream":"live_fixture(",
 "jetstream_checkpoint_rejects_unavailable_server_instead_of_skipping":"async_nats::connect(",
 "jetstream_checkpoint_uses_global_revision_not_store_generation":"live_fixture(",
 "complete_receipt_validation_precedes_suppression_and_failures_forward":"exact_artifact(",
 "topology_validator_binds_every_tuple_to_owner_block":"topology_input(",
}
reasons=[]
for target,fqn in rows:
    name=fqn.rsplit("::",1)[-1]
    pattern=rf'#\[ignore = "(requires [^"]+)"\]\s+(?:async\s+)?fn\s+{re.escape(name)}\s*\('
    matches=re.findall(pattern,texts[target])
    if len(matches)!=1: raise SystemExit(f"ci_harness_registration[ignore:{target}:{fqn}:{len(matches)}]")
    reason=matches[0]
    if not re.search(r"NATS|JetStream|credential|topology|artifact",reason,re.I):
        raise SystemExit(f"ci_harness_registration[non-external:{fqn}:{reason}]")
    start=texts[target].find(f"fn {name}")
    if start<0: raise SystemExit(f"ci_harness_registration[function-missing:{fqn}]")
    ends=[value for marker in ("\n#[", "\n    #[") if (value:=texts[target].find(marker,start+3))>=0]
    body=texts[target][start:min(ends) if ends else len(texts[target])]
    anchor=seam_anchors.get(fqn)
    if anchor is None or anchor not in body:
        raise SystemExit(f"ci_harness_registration[external-seam:{fqn}:{anchor}]")
    reasons.append(reason)
if set(seam_anchors)!={fqn for _,fqn in rows}: raise SystemExit("ci_harness_registration[seam-inventory]")
source_ignored=[]
for target,text in texts.items():
    for reason,name in re.findall(r'#\[ignore = "([^"]+)"\]\s+(?:async\s+)?fn\s+([A-Za-z0-9_]+)\s*\(',text):
        source_ignored.append((target,name,reason))
for target,name,reason in source_ignored:
    compiled=[fqn for row_target,fqn in rows if row_target==target and fqn.rsplit("::",1)[-1]==name]
    if len(compiled)!=1: raise SystemExit(f"ci_harness_registration[source-ignored-not-compiled:{target}:{name}:{len(compiled)}]")
if len(source_ignored)!=len(rows): raise SystemExit(f"ci_harness_registration[source-vs-compiled:{len(source_ignored)}:{len(rows)}]")
pure="deadline_state_machine_tests::deadline_state_machine_is_receipt_anchored_and_mutation_sensitive"
ordinary_rows=[tuple(line.rstrip("\n").split("\t")) for line in ordinary.open()]
if ordinary_rows.count(("lib",pure))!=1 or pure in {fqn for _,fqn in rows}:
    raise SystemExit("ci_harness_registration[pure-ordinary-compiled]")
print(f"ci_harness_registration targets={len(target_rows)} ignored={len(rows)} external_reasons={len(reasons)} external_seams={len(seam_anchors)} exact_fqns={len(set(fqn for _,fqn in rows))} pure_ordinary=1 passed=1")
PY
}

ci_harness_record_passed() {
  local target="$1" fqn="$2" output="$3"
  [ -n "${PHASE285_CI_HARNESS_EXECUTION_TRANSCRIPT:-}" ] || return 0
  python3 -I - "$output" "$fqn" <<'PY'
import re,sys
text=open(sys.argv[1],encoding="utf-8").read(); fqn=sys.argv[2]
running=re.findall(r"^running (\d+) test",text,re.M)
summary=re.findall(r"^test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored; \d+ measured; (\d+) filtered out;",text,re.M)
named=re.findall(rf"^test {re.escape(fqn)} \.\.\. ok$",text,re.M)
if running!=["1"] or len(summary)!=1 or summary[0][:3]!=("1","0","0") or len(named)!=1:
    raise SystemExit(f"ci_harness_record[non-exact:{fqn}:{running}:{summary}:{len(named)}]")
PY
  printf '%s\t%s\n' "$target" "$fqn" >>"$PHASE285_CI_HARNESS_EXECUTION_TRANSCRIPT"
}

ci_harness_validate_execution_transcript() {
  python3 -I - "$1" "$2" <<'PY'
import sys
def rows(path):
    result=[]
    for line in open(path,encoding="utf-8"):
        fields=line.rstrip("\n").split("\t")
        if len(fields)!=2 or not all(fields): raise SystemExit("ci_harness_execution[malformed]")
        result.append(tuple(fields))
    return result
expected=rows(sys.argv[1]); observed=rows(sys.argv[2])
if len(observed)!=len(set(observed)): raise SystemExit("ci_harness_execution[duplicate]")
if sorted(observed)!=sorted(expected):
    raise SystemExit(f"ci_harness_execution[mismatch:missing={sorted(set(expected)-set(observed))}:extra={sorted(set(observed)-set(expected))}]")
print(f"ci_harness_execution exact={len(observed)} unique={len(set(observed))} passed=1")
PY
}

run_ignored_exact_test() {
  local target="$1" fqn="$2" output="$3"
  if [ "$target" = lib ]; then
    cargo test -p swarm-governance-witness --lib --locked --offline -- --test-threads=1 --ignored "$fqn" --exact >"$output" 2>&1
  else
    cargo test -p swarm-governance-witness --test "$target" --locked --offline -- --test-threads=1 --ignored "$fqn" --exact >"$output" 2>&1
  fi
  python3 -I - "$output" "$fqn" <<'PY'
import re,sys
text=open(sys.argv[1],encoding="utf-8").read(); fqn=sys.argv[2]
running=re.findall(r"^running (\d+) test",text,re.M)
summary=re.findall(r"^test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored; \d+ measured; (\d+) filtered out;",text,re.M)
named=re.findall(rf"^test {re.escape(fqn)} \.\.\. ok$",text,re.M)
if running!=["1"]: raise SystemExit(f"ci_harness_exact[running:{fqn}:{running}]")
if len(summary)!=1 or summary[0][:3]!=("1","0","0") or len(named)!=1: raise SystemExit(f"ci_harness_exact[summary:{fqn}:{summary}:{len(named)}]")
print(f"ci_harness_exact fqn={fqn} running=1 passed=1 failed=0 ignored=0 filtered_out={summary[0][3]}")
PY
  ci_harness_record_passed "$target" "$fqn" "$output"
}

ci_harness_route_inventory() {
  cat <<'EOF'
deadline
observation
transport
grants
jetstream-cas
jetstream-checkpoint
full-service-path
receipt-topology
EOF
}

ci_harness_route_members() {
  case "$1" in
    deadline) cat <<'EOF'
lib	deadline_state_machine_tests::subscriber_callsite_is_receipt_anchored_and_mutation_sensitive
full_service_path	full_service_path_constructor_deadline_is_exact_and_receipt_bound
EOF
      ;;
    observation) printf '%s\t%s\n' lib service_checkpoint_observation_tests::worker_observations_are_real_and_reconciled ;;
    transport) printf '%s\t%s\n' lib service_checkpoint_transport_semantics_tests::post_command_other_is_distinct_from_pre_send_drain ;;
    grants) printf '%s\t%s\n' lib service_checkpoint_transport_semantics_tests::public_and_private_expired_response_grants_recover_exactly_once ;;
    jetstream-cas) cat <<'EOF'
jetstream_cas	jetstream_cas_rejects_wrong_revision_header_or_ack
jetstream_cas	jetstream_cas_confirms_raw_sequence_and_bytes
jetstream_cas	jetstream_cas_rejects_del_purge_rollup_and_direct_reads
EOF
      ;;
    jetstream-checkpoint) cat <<'EOF'
jetstream_checkpoint	jetstream_checkpoint_survives_restart_for_current_predecessor_prepared_abort_and_genesis
jetstream_checkpoint	jetstream_checkpoint_rejects_rolled_back_anchor_or_recreated_stream
jetstream_checkpoint	jetstream_checkpoint_rejects_unavailable_server_instead_of_skipping
jetstream_checkpoint	jetstream_checkpoint_uses_global_revision_not_store_generation
EOF
      ;;
    full-service-path) cat <<'EOF'
full_service_path	production_initializer_creates_reopens_and_reproduces_ready
full_service_path	full_service_path_rejects_runtime_private_subject_and_store_raw_api
full_service_path	full_service_path_rejects_credential_account_and_mount_swaps
full_service_path	full_service_path_validates_proxy_response_before_public_attestation
full_service_path	full_service_path_fails_closed_on_store_queue_exhaustion
EOF
      ;;
    receipt-topology) cat <<'EOF'
lib	service_checkpoint_relay_tests::complete_receipt_authority_and_grants_are_observed
service_checkpoint	complete_receipt_validation_precedes_suppression_and_failures_forward
service_checkpoint	topology_validator_binds_every_tuple_to_owner_block
EOF
      ;;
    *) echo "unknown CI harness route: $1" >&2; return 2 ;;
  esac
}

ci_harness_dispatch_route() {
  local route="$1" output
  if [ "${PHASE285_CI_HARNESS_TRANSCRIPT_ONLY:-0}" = 1 ]; then
    ci_harness_route_members "$route"
    return
  fi
  case "$route" in
    deadline) run_service_checkpoint_deadline_focus ;;
    observation) run_service_checkpoint_observation_focus ;;
    transport)
      output="$(mktemp "${PHASE285_CI_ROUTE_TEMP_PARENT:-${SWARM_NATS_HARNESS_SCRATCH:?}}/ci-transport.XXXXXX")"
      run_ignored_exact_test lib service_checkpoint_transport_semantics_tests::post_command_other_is_distinct_from_pre_send_drain "$output"
      rm -f -- "$output"
      ;;
    grants)
      output="$(mktemp "${PHASE285_CI_ROUTE_TEMP_PARENT:-${SWARM_NATS_HARNESS_SCRATCH:?}}/ci-grants.XXXXXX")"
      run_ignored_exact_test lib service_checkpoint_transport_semantics_tests::public_and_private_expired_response_grants_recover_exactly_once "$output"
      rm -f -- "$output"
      ;;
    jetstream-cas) run_selector jetstream-cas ;;
    jetstream-checkpoint) run_selector jetstream-checkpoint ;;
    full-service-path) run_selector full-service-path ;;
    receipt-topology)
      topology_owner_block_focus
      run_relay_recreation_mutants_for_ci
      ;;
    *) echo "unknown CI harness route: $route" >&2; return 2 ;;
  esac
}

ci_harness_dispatch_transcript() {
  local expected="$1" transcript route expected_parent
  expected_parent="$(cd -- "$(dirname -- "$expected")" && pwd -P)"
  transcript="$(mktemp "$expected_parent/ci-dispatch.XXXXXX")"
  : >"$transcript"
  while IFS= read -r route; do
    [ -n "$route" ] || continue
    PHASE285_CI_HARNESS_TRANSCRIPT_ONLY=1 ci_harness_dispatch_route "$route" >>"$transcript"
  done < <(ci_harness_route_inventory)
  ci_harness_validate_execution_transcript "$expected" "$transcript"
  rm -f -- "$transcript"
}

ci_harness_registration_guard() {
  local mode="${1:-normal}" scratch inventory current_output
  scratch="$(phase285_create_confined_scratch phase285-ci-registration)"
  PHASE285_WITNESS_TEMP_DIR="$scratch"
  trap cleanup_temp_dir_on_exit EXIT
  inventory="$scratch/compiled-ignored.tsv"
  ci_harness_compiled_ignored_inventory "$inventory"
  ci_harness_source_reason_guard "$inventory"
  current_output="$scratch/current-dispatch.txt"
  bash "$ROOT_DIR/tools/check-phase285-witness-conformance.sh" --self-test ci-harness-dispatch-transcript "$inventory" >"$current_output"
  grep -Eq '^ci_harness_execution exact=[1-9][0-9]* unique=[1-9][0-9]* passed=1$' "$current_output" || {
    cat "$current_output" >&2
    return 1
  }
  if [ "$mode" = self-test ]; then
    python3 -I - "$ROOT_DIR" "$scratch" "$inventory" "${inventory}.targets.tsv" <<'PY'
import hashlib,os,pathlib,shlex,shutil,stat,subprocess,sys
root=pathlib.Path(sys.argv[1]); scratch=pathlib.Path(sys.argv[2]); inventory=pathlib.Path(sys.argv[3]); targets=pathlib.Path(sys.argv[4])
source=(root/"tools/check-phase285-witness-conformance.sh").read_text()
root_anchor='ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"'
if source.find(root_anchor)>256: raise SystemExit("ci_harness_registration[root-anchor]")
source=source.replace(root_anchor,f'ROOT_DIR="{root}"',1)
mutations={
 "omission":("observation\ntransport\ngrants\n","observation\ngrants\n"),
 "addition":("observation\ntransport\ngrants\n","observation\ntransport\nforeign-route\ngrants\n"),
 "duplication":("observation\ntransport\ngrants\n","observation\ntransport\ngrants\ngrants\n"),
 "substitution":("observation) printf '%s\\t%s\\n' lib service_checkpoint_observation_tests::worker_observations_are_real_and_reconciled ;;","observation) printf '%s\\t%s\\n' lib service_checkpoint_observation_tests::worker_observations_are_real_and_reconciled_substituted ;;"),
}
for label,(old,new) in mutations.items():
    if source.count(old)!=1: raise SystemExit(f"ci_harness_registration[{label}:anchor:{source.count(old)}]")
    path=scratch/f"checker-{label}.sh"; path.write_text(source.replace(old,new,1)); path.chmod(0o700)
    result=subprocess.run(["bash",str(path),"--self-test","ci-harness-dispatch-transcript",str(inventory)],cwd=root,env=os.environ.copy(),text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
    if result.returncode==0: raise SystemExit(f"ci_harness_registration[survived:{label}]\n{result.stdout}")
    print(f"ci_harness_registration_mutation_red mutation={label} dispatcher_executed=1 killed=1")

tracked=subprocess.check_output(["git","-C",str(root),"ls-files","-z"]).split(b"\0")
tracked=[os.fsdecode(name) for name in tracked if name]
tracked_inventory=subprocess.check_output(["git","-C",str(root),"ls-files","-z"])
status_inventory=subprocess.check_output(["git","-C",str(root),"status","--porcelain=v1","-z"])
git_dir=subprocess.check_output(
    ["git","-C",str(root),"rev-parse","--path-format=absolute","--git-dir"],
    text=True,
).strip()

def file_identity(path):
    metadata=path.lstat()
    if stat.S_ISLNK(metadata.st_mode):
        return ("symlink",stat.S_IMODE(metadata.st_mode),os.readlink(path))
    if not stat.S_ISREG(metadata.st_mode):
        raise SystemExit(f"ci_harness_registration[projection-source-type:{path}]")
    return ("regular",stat.S_IMODE(metadata.st_mode),hashlib.sha256(path.read_bytes()).hexdigest())

subject_identities={relative:file_identity(root/relative) for relative in tracked}

def copied_workspace(label):
    workspace=scratch/f"workspace-{label}"
    workspace.mkdir()
    for relative in tracked:
        original=root/relative; copied=workspace/relative
        copied.parent.mkdir(parents=True,exist_ok=True)
        if original.is_symlink(): copied.symlink_to(os.readlink(original))
        elif original.is_file(): shutil.copy2(original,copied)
    copied_identities={relative:file_identity(workspace/relative) for relative in tracked}
    if copied_identities!=subject_identities:
        raise SystemExit(f"ci_harness_registration[{label}:initial-byte-identity]")
    (workspace/".git").write_text(f"gitdir: {git_dir}\n")
    checker=workspace/"tools/check-phase285-witness-conformance.sh"
    checker_source=checker.read_text()
    if checker_source.find(root_anchor)>256: raise SystemExit(f"ci_harness_registration[{label}:root-anchor]")
    private=checker.with_suffix(".private")
    private.write_text(checker_source.replace(root_anchor,f'ROOT_DIR="{workspace}"',1))
    private.chmod(0o700)
    os.replace(private,checker)
    temp_parent=scratch/f"tmp-{label}"
    temp_parent.mkdir(mode=0o700)
    cargo_temp=scratch/f"cargo-tmp-{label}"
    cargo_temp.mkdir(mode=0o700)
    wrapper_parent=scratch/f"cargo-wrapper-{label}"
    wrapper_parent.mkdir(mode=0o700)
    real_cargo=shutil.which("cargo")
    if real_cargo is None: raise SystemExit(f"ci_harness_registration[{label}:cargo-absent]")
    cargo_wrapper=wrapper_parent/"cargo"
    cargo_wrapper.write_text(
        "#!/bin/bash\n"
        f"export TMPDIR={shlex.quote(str(cargo_temp))}\n"
        f"exec {shlex.quote(real_cargo)} \"$@\"\n"
    )
    cargo_wrapper.chmod(0o700)
    target_parent=scratch/f"target-{label}"
    return workspace,checker,temp_parent,cargo_temp,wrapper_parent,target_parent

def copied_environment(temp_parent,wrapper_parent,target_parent):
    environment=os.environ.copy()
    environment["TMPDIR"]=str(temp_parent)
    environment["CARGO_TARGET_DIR"]=str(target_parent)
    environment["PATH"]=str(wrapper_parent)+os.pathsep+environment["PATH"]
    if sys.platform == "darwin":
        environment["SDKROOT"]=subprocess.check_output(
            ["/usr/bin/xcrun","--show-sdk-path"], text=True
        ).strip()
    return environment

def recursive_temp_inventory(temp_parent):
    return sorted(
        path.relative_to(temp_parent).as_posix()
        for path in temp_parent.rglob("*")
    )

workspace,checker,temp_parent,cargo_temp,wrapper_parent,target_parent=copied_workspace("new-target")
new_target=workspace/"crates/swarm-governance-witness/tests/new_live.rs"
new_target.write_text(
    '#[test]\n#[ignore = "requires an external NATS topology"]\n'
    'fn unregistered_external_topology() {}\n'
)
environment=copied_environment(temp_parent,wrapper_parent,target_parent)
result=subprocess.run(
    ["bash",str(checker),"--self-test","ci-harness-registration-validate"],
    cwd=workspace,env=environment,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,
)
expected="ci_harness_registration[external-seam:unregistered_external_topology:None]"
if result.returncode==0 or expected not in result.stdout:
    raise SystemExit(f"ci_harness_registration[new-target-wrong-reason:{result.returncode}]\n{result.stdout}")
residue=recursive_temp_inventory(temp_parent)
if residue: raise SystemExit(f"ci_harness_registration[new-target-residue:{residue}]")
shutil.rmtree(target_parent)
if target_parent.exists(): raise SystemExit("ci_harness_registration[new-target-target-residue]")
shutil.rmtree(cargo_temp); shutil.rmtree(wrapper_parent)
if cargo_temp.exists() or wrapper_parent.exists(): raise SystemExit("ci_harness_registration[new-target-owned-tool-residue]")
print("ci_harness_registration_mutation_red mutation=auto-discovered-ignored-target compiled=1 killed=1 intended=external-seam")

workspace,checker,temp_parent,cargo_temp,wrapper_parent,target_parent=copied_workspace("pure-attribute")
library=workspace/"crates/swarm-governance-witness/src/lib.rs"
library_source=library.read_text()
pure_anchor="    #[test]\n    fn deadline_state_machine_is_receipt_anchored_and_mutation_sensitive()"
if library_source.count(pure_anchor)!=1: raise SystemExit("ci_harness_registration[pure-attribute-anchor]")
private=library.with_suffix(".private")
private.write_text(library_source.replace(pure_anchor,pure_anchor.replace("#[test]","#[cfg(test)]"),1))
os.replace(private,library)
environment=copied_environment(temp_parent,wrapper_parent,target_parent)
result=subprocess.run(
    ["bash",str(checker),"--self-test","ci-harness-registration-validate"],
    cwd=workspace,env=environment,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,
)
expected="ci_harness_registration[pure-ordinary-compiled]"
if result.returncode==0 or expected not in result.stdout:
    raise SystemExit(f"ci_harness_registration[pure-attribute-wrong-reason:{result.returncode}]\n{result.stdout}")
residue=recursive_temp_inventory(temp_parent)
if residue: raise SystemExit(f"ci_harness_registration[pure-attribute-residue:{residue}]")
shutil.rmtree(target_parent)
if target_parent.exists(): raise SystemExit("ci_harness_registration[pure-attribute-target-residue]")
shutil.rmtree(cargo_temp); shutil.rmtree(wrapper_parent)
if cargo_temp.exists() or wrapper_parent.exists(): raise SystemExit("ci_harness_registration[pure-attribute-owned-tool-residue]")
print("ci_harness_registration_mutation_red mutation=pure-test-attribute compiled=1 killed=1 intended=pure-ordinary-compiled")

if subprocess.check_output(["git","-C",str(root),"ls-files","-z"])!=tracked_inventory:
    raise SystemExit("ci_harness_registration[subject-tracked-inventory-changed]")
if subprocess.check_output(["git","-C",str(root),"status","--porcelain=v1","-z"])!=status_inventory:
    raise SystemExit("ci_harness_registration[subject-status-inventory-changed]")
if {relative:file_identity(root/relative) for relative in tracked}!=subject_identities:
    raise SystemExit("ci_harness_registration[subject-byte-identity-changed]")

target_count=sum(1 for line in targets.read_text().splitlines() if line)
print(f"ci_harness_registration_self_test mutations={len(mutations)+2} compiled_targets={target_count} dispatcher_executions={len(mutations)+1} copied_workspaces=2 subject_writes=0 vacuous=0 passed=1")
PY
  elif [ "$mode" != normal ]; then
    echo "unknown CI harness registration mode: $mode" >&2
    return 2
  fi
  cleanup_temp_dir
  trap - EXIT
}

run_service_checkpoint_ci_harness() {
  local accepted_tree="${PHASE285_SERVICE_CHECKPOINT_TREE:?PHASE285_SERVICE_CHECKPOINT_TREE required}"
  local route harness_parent inventory_parent route_parent expected observed exact_count
  [[ "$accepted_tree" =~ ^[0-9a-f]{40}$ ]] || { echo "CI harness tree is malformed" >&2; return 1; }
  ci_harness_registration_guard self-test
  harness_parent="$(phase285_create_confined_scratch phase285-ci-harness)"
  inventory_parent="$harness_parent/inventory"
  route_parent="$harness_parent/routes"
  mkdir -m 700 -- "$inventory_parent" "$route_parent"
  expected="$inventory_parent/compiled-ignored.tsv"
  observed="$inventory_parent/executed.tsv"
  : >"$observed"
  PHASE285_WITNESS_TEMP_DIR="$harness_parent"
  trap cleanup_temp_dir_on_exit EXIT
  ci_harness_compiled_ignored_inventory "$expected"
  export PHASE285_CI_HARNESS_EXECUTION_TRANSCRIPT="$observed"
  while IFS= read -r route; do
    [ -n "$route" ] || continue
    (
      export TMPDIR="$route_parent" PHASE285_CI_ROUTE_TEMP_PARENT="$route_parent"
      ci_harness_dispatch_route "$route"
    )
    [ -z "$(phase285_boundary_child_inventory "$route_parent")" ] || {
      echo "CI harness route left confined scratch residue: route=$route" >&2
      return 1
    }
    echo "ci_harness_route_residue route=$route child_paths=0 passed=1"
  done < <(ci_harness_route_inventory)
  ci_harness_validate_execution_transcript "$expected" "$observed"
  exact_count="$(wc -l <"$observed" | tr -d ' ')"
  cleanup_temp_dir
  trap - EXIT
  [ ! -e "$harness_parent" ] || { echo "CI harness cleanup left its owned parent behind" >&2; return 1; }
  echo "service_checkpoint_ci_harness ignored_fqns=$exact_count exact=$exact_count non_vacuous=$exact_count topology=relay artifacts=required passed=1"
}

case "${1:-}" in
  --focused-service-checkpoint-r1a-corpus)
    [ "$#" -eq 1 ] || { echo "usage: $0 --focused-service-checkpoint-r1a-corpus" >&2; exit 2; }
    run_service_checkpoint_r1a_corpus
    ;;
  --focused-service-checkpoint-transport-semantics)
    [ "$#" -eq 1 ] || { echo "usage: $0 --focused-service-checkpoint-transport-semantics" >&2; exit 2; }
    run_service_checkpoint_transport_semantics_focus
    ;;
  --focused-service-checkpoint-readiness-controls)
    [ "$#" -eq 1 ] || { echo "usage: $0 --focused-service-checkpoint-readiness-controls" >&2; exit 2; }
    run_service_checkpoint_readiness_focus
    ;;
  --focused-service-checkpoint-grants)
    [ "$#" -eq 1 ] || { echo "usage: $0 --focused-service-checkpoint-grants" >&2; exit 2; }
    run_service_checkpoint_grant_focus
    ;;
  --focused-service-checkpoint-grant-recovery-positive)
    [ "$#" -eq 1 ] || { echo "usage: $0 --focused-service-checkpoint-grant-recovery-positive" >&2; exit 2; }
    run_service_checkpoint_grant_recovery_positive_focus
    ;;
  --focused-service-checkpoint-held-public-controls)
    [ "$#" -eq 1 ] || { echo "usage: $0 --focused-service-checkpoint-held-public-controls" >&2; exit 2; }
    run_service_checkpoint_held_public_controls_focus
    ;;
  --focused-service-checkpoint-r1a-control)
    [ "$#" -eq 2 ] || { echo "usage: $0 --focused-service-checkpoint-r1a-control R1A-C06|R1A-C07|R1A-C10|R1A-C11|R1A-C17|R1A-C18|R1A-C19|R1A-C20|R1A-C21|R1A-C22|R1A-C23" >&2; exit 2; }
    run_service_checkpoint_r1a_control_focus "$2"
    ;;
  --focused-service-checkpoint-relay-positive)
    [ "$#" -eq 1 ] || { echo "usage: $0 --focused-service-checkpoint-relay-positive" >&2; exit 2; }
    run_service_checkpoint_relay_positive_focus
    ;;
  --focused-service-checkpoint-relay-recreation-source)
    [ "$#" -eq 1 ] || { echo "usage: $0 --focused-service-checkpoint-relay-recreation-source" >&2; exit 2; }
    relay_recreation_source_guard
    ;;
  --focused-service-checkpoint-relay-recreation-positive)
    [ "$#" -eq 1 ] || { echo "usage: $0 --focused-service-checkpoint-relay-recreation-positive" >&2; exit 2; }
    run_service_checkpoint_relay_positive_focus
    ;;
  --focused-service-checkpoint-observations)
    [ "$#" -eq 1 ] || { echo "usage: $0 --focused-service-checkpoint-observations" >&2; exit 2; }
    run_service_checkpoint_observation_focus
    ;;
  --focused-service-checkpoint-deadline)
    [ "$#" -eq 1 ] || { echo "usage: $0 --focused-service-checkpoint-deadline" >&2; exit 2; }
    run_service_checkpoint_deadline_focus
    ;;
  --focused-service-process-safety)
    [ "$#" -eq 1 ] || { echo "usage: $0 --focused-service-process-safety" >&2; exit 2; }
    run_service_process_safety_focus
    ;;
  --focused-service-operational-bounds)
    [ "$#" -eq 1 ] || { echo "usage: $0 --focused-service-operational-bounds" >&2; exit 2; }
    run_service_operational_bounds_focus
    ;;
  --focused-service-secret-files)
    [ "$#" -eq 1 ] || { echo "usage: $0 --focused-service-secret-files" >&2; exit 2; }
    run_service_secret_files_focus
    ;;
  --focused-service-checkpoint-ci-harness)
    [ "$#" -eq 1 ] || { echo "usage: $0 --focused-service-checkpoint-ci-harness" >&2; exit 2; }
    run_service_checkpoint_ci_harness
    ;;
  --self-test)
    if [ "$#" -eq 4 ] && [ "$2" = complete-receipt-real-signal ]; then
      case "$3" in EXIT|HUP|INT|TERM) ;; *) echo "complete receipt signal is invalid" >&2; exit 2 ;; esac
      [[ "$4" = /* ]] || { echo "complete receipt signal root must be absolute" >&2; exit 2; }
      run_complete_receipt_focus "$3" "$4"
    elif [ "$#" -eq 2 ] && [ "$2" = transport-layering-zero-or-omitted ]; then
      run_transport_execution_self_test
    elif [ "$#" -eq 2 ] && [ "$2" = store-proxy-source ]; then
      store_proxy_source_guard normal
      store_proxy_source_guard self-test
    elif [ "$#" -eq 2 ] && [ "$2" = service-checkpoint-observation-source ]; then
      observation_source_guard normal
      observation_source_guard self-test
    elif [ "$#" -eq 2 ] && [ "$2" = transport-semantics-source ]; then
      transport_semantics_source_guard normal
      transport_semantics_source_guard self-test
    elif [ "$#" -eq 2 ] && [ "$2" = transport-semantics-registry ]; then
      transport_semantics_registry_guard
    elif [ "$#" -eq 2 ] && [ "$2" = relay-recreation-mutants ]; then
      run_relay_recreation_mutants
    elif [ "$#" -eq 2 ] && [ "$2" = relay-recreation-mutant-sources ]; then
      relay_recreation_canonical_route_guard self-test
      PHASE285_RELAY_RECREATION_SOURCE_ONLY=1 run_relay_recreation_mutants
    elif [ "$#" -eq 2 ] && [ "$2" = complete-receipt-suppression ]; then
      run_complete_receipt_focus
    elif [ "$#" -eq 2 ] && [ "$2" = topology-owner-blocks ]; then
      topology_owner_block_focus
    elif [ "$#" -eq 2 ] && [ "$2" = jetstream-release-hook ]; then
      run_release_hook_self_test
    elif [ "$#" -eq 2 ] && [ "$2" = jetstream-iterator-source ]; then
      checkpoint_iterator_source_guard \
        "$ROOT_DIR/crates/swarm-governance-witness/src/jetstream_store.rs" self-test
    elif [ "$#" -eq 2 ] && [ "$2" = transport-positive-readiness-parser ]; then
      transport_positive_readiness_parser_self_test
    elif [ "$#" -eq 3 ] && [ "$2" = ci-harness-dispatch-transcript ]; then
      ci_harness_dispatch_transcript "$3"
    elif [ "$#" -eq 2 ] && [ "$2" = ci-harness-registration ]; then
      ci_harness_registration_guard self-test
    elif [ "$#" -eq 2 ] && [ "$2" = ci-harness-registration-validate ]; then
      ci_harness_registration_guard normal
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
      echo "usage: $0 --self-test [transport-layering-zero-or-omitted|store-proxy-source|service-checkpoint-observation-source|transport-semantics-source|transport-semantics-registry|relay-recreation-mutants|relay-recreation-mutant-sources|complete-receipt-suppression|topology-owner-blocks|jetstream-release-hook|jetstream-iterator-source|jetstream-iterator-ledger|transport-positive-readiness-parser|ci-harness-registration]" >&2
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
