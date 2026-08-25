#!/usr/bin/env bash
# Exact, non-vacuous Phase 285 witness conformance selector runner.
set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

PHASE285_WITNESS_TEMP_DIR=""
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

# Plans 01-02 materialize exactly these twenty cases. Later owners must extend
# this inventory before adding another case, so an extra test is red.
materialized_inventory() {
  selector_rows response-failure-wire
  selector_rows candidate-verifier
  selector_rows protocol-checkpoint
  selector_rows atomic-store-contract
  selector_rows in-memory-differential
  selector_rows typed-proxy
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
  case "$selector" in
    response-failure-wire|candidate-verifier|protocol-checkpoint|atomic-store-contract|in-memory-differential|typed-proxy) ;;
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
  materialized_inventory | LC_ALL=C sort >"$inventory_file"
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
  target_count="$(wc -l <"$inventory_file" | tr -d ' ')"
  expected_filtered=$((target_count - 1))
  while IFS= read -r case_name; do
    [ -n "$case_name" ] || continue
    output_file="$temp_dir/$case_name.txt"
    if ! cargo test -p "$package" --test "$target" --locked --offline -- "$case_name" --exact >"$output_file" 2>&1; then
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
    executed=$((executed + 1))
    echo "case=$case_name running=1 passed=1 failed=0 ignored=0 filtered_out=$expected_filtered"
  done < <(selector_rows "$selector")
  local required
  required="$(selector_rows "$selector" | sed '/^$/d' | wc -l | tr -d ' ')"
  [ "$executed" -eq "$required" ] || {
    echo "selector omitted rows: selector=$selector executed=$executed required=$required" >&2
    return 1
  }
  run_self_test_for_selector "$selector"
  echo "selector=$selector executed=$executed passed=$executed failed=0 ignored=0 mutation_failure_count=8"
}

case "${1:-}" in
  --self-test)
    if [ "$#" -eq 2 ] && [ "$2" = transport-layering-zero-or-omitted ]; then
      run_transport_execution_self_test
    elif [ "$#" -eq 1 ]; then
      run_self_tests
    else
      echo "usage: $0 --self-test [transport-layering-zero-or-omitted]" >&2
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
