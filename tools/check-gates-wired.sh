#!/usr/bin/env bash
#
# Gate-wiring scanner (task #15).
#
# WHY THIS EXISTS
#   Three gate scripts -- check-platform-openapi.sh,
#   check-adversary-emulation-coverage.sh and
#   check-stigmergic-feedback-benchmark.sh -- sat in tools/ for months invoked by
#   no workflow at all, and tools/verify-release-hardening.sh, which proves that
#   `-C panic=abort` and `-C overflow-checks=on` actually reach the release rustc
#   invocations for the two binaries the container ships, had never run anywhere.
#   Nothing detected any of that. A human noticed by reading the directory.
#
#   A gate that never runs is not a gate, it is a file that looks like one. That
#   is the same shape as every entry in .planning/STATE.md's defect catalogue: a
#   check reporting success over a region it never inspected. This script makes
#   the omission mechanical.
#
# WHAT IS COVERED
#   Every `tools/check-*.sh` and `tools/verify-*.sh`, tracked or untracked
#   (`git ls-files -c -o --exclude-standard`, the same enumeration
#   check-fixture-freshness.sh:47 uses, so a NEW script counts on the commit that
#   adds it rather than the commit after). Each must be named by the `run:`
#   command of at least one step of at least one job in some
#   `.github/workflows/*.yml`.
#
#   `generate-*.sh` and `measure-*.sh` are deliberately out of scope: they
#   produce artifacts, they do not assert anything, and an unrun generator is not
#   a false assurance. `with-nats-jetstream.sh` is a harness, not a gate.
#
# WHY THIS IS NOT `grep -q tools/x.sh .github/workflows/*.yml`
#   Because grep would count all of these as "wired":
#     - a mention inside a `#` comment
#     - a path in an `on: push: paths:` filter
#     - a step guarded by `if: false`
#     - the string appearing in an unrelated `env:` value
#   Counting a name-match as a behaviour-match is the "swept by grepping
#   identifier names" pattern STATE.md records three separate times. So the scan
#   below walks the workflow structure -- jobs, steps, `run:` scalars -- and only
#   a real `run:` command counts.
#
#   The parser is a deliberately small indentation scanner over the block-mapping
#   subset GitHub workflows use, written against the python3 standard library
#   because ubuntu-latest is only guaranteed to ship that (four already-wired
#   gates rely on plain python3; none relies on PyYAML). It was cross-checked
#   against PyYAML's parse of both current workflows -- same jobs, same step
#   count, same `run:` text -- before landing.
#
# CONDITIONAL STEPS
#   A step or job carrying an `if:` is only conditionally wired, so an `if:` is
#   rejected by default. Two expressions are allowed because they can only make a
#   step run MORE often than the default: `always()` and `!cancelled()`. Anything
#   else has to be argued for in review, which is the point.
#
# REFUSING TO PASS SILENTLY
#   Four guards, all mandatory (precedent: check-fixture-freshness.sh:53-56). An
#   empty script list, an empty workflow list, a workflow that parses to zero
#   jobs, or a parse that finds zero `run:` steps anywhere are all treated as
#   failures. Those are exactly the states in which a broken scanner would
#   otherwise report "all gates wired" over a region it never inspected.
set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

phase285_self_test() {
  local plan01_owned=(
    tools/check-phase285-witness-conformance.sh
    tools/check-phase285-deployment.sh
    tools/check-phase285-closure.sh
    tools/check-phase285-evidence.sh
    tools/check-phase285-plan-schema.sh
  )
  local path
  for path in "${plan01_owned[@]}"; do
    if [ ! -f "$path" ] || [ ! -x "$path" ]; then
      echo "missing or non-executable Plan 01 Phase 285 checker: $path" >&2
      return 1
    fi
  done
  if [ -e tools/check-phase285-governance-persistence.sh ] &&
    [ ! -x tools/check-phase285-governance-persistence.sh ]; then
    echo "Plan 05A governance checker exists but is not executable" >&2
    return 1
  fi

  if [ -x tools/check-phase285-governance-persistence.sh ]; then
    bash tools/check-phase285-governance-persistence.sh --self-test
    echo "phase285_governance_self_test owner=Plan05A materialized=1"
  else
    local missing_status=0
    bash tools/check-phase285-governance-persistence.sh --self-test >/dev/null 2>&1 || missing_status=$?
    if [ "$missing_status" -eq 0 ]; then
      echo "absent Plan 05A governance checker passed unexpectedly" >&2
      return 1
    fi
    echo "phase285_missing_governance_self_test expected_nonzero=1 observed_status=$missing_status"
  fi
}

PHASE285_GLOBAL_MODE=normal
PHASE285_BASE_COMMIT=""
if [ "${1:-}" = --phase285-self-test ]; then
  [ "$#" -eq 1 ] || { echo "usage: $0 [--phase285-self-test]" >&2; exit 2; }
  PHASE285_GLOBAL_MODE=self-test
elif [ "${1:-}" = --phase285-differential ]; then
  [ "$#" -eq 2 ] || {
    echo "usage: $0 [--phase285-self-test | --phase285-differential BASE_COMMIT]" >&2
    exit 2
  }
  PHASE285_GLOBAL_MODE=differential
  PHASE285_BASE_COMMIT="$2"
elif [ "$#" -ne 0 ]; then
  echo "usage: $0 [--phase285-self-test | --phase285-differential BASE_COMMIT]" >&2
  exit 2
fi

# `mapfile` is bash 4+; macOS ships 3.2 and this gate has to run locally too.
scripts=()
while IFS= read -r path; do
  [ -n "$path" ] || continue
  scripts+=("$path")
done < <(
  git ls-files -c -o --exclude-standard -- 'tools/check-*.sh' 'tools/verify-*.sh' \
    | LC_ALL=C sort -u
)

if [ "${#scripts[@]}" -eq 0 ]; then
  echo "no tools/check-*.sh or tools/verify-*.sh found; refusing to pass silently" >&2
  exit 1
fi

workflows=()
while IFS= read -r path; do
  [ -n "$path" ] || continue
  workflows+=("$path")
done < <(
  git ls-files -c -o --exclude-standard -- '.github/workflows/*.yml' '.github/workflows/*.yaml' \
    | LC_ALL=C sort -u
)

if [ "${#workflows[@]}" -eq 0 ]; then
  echo "no .github/workflows/*.yml found; refusing to pass silently" >&2
  exit 1
fi

if [ "$PHASE285_GLOBAL_MODE" = normal ]; then
  echo "checking ${#scripts[@]} gate script(s) against ${#workflows[@]} workflow(s)"
fi

python3 -I - "$PHASE285_GLOBAL_MODE" "$PHASE285_BASE_COMMIT" \
  "${#scripts[@]}" "${scripts[@]}" "${workflows[@]}" <<'PY'
import contextlib
import fnmatch
import hashlib
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile

mode = sys.argv[1]
requested_base = sys.argv[2]
script_count = int(sys.argv[3])
scripts = sys.argv[4 : 4 + script_count]
workflows = sys.argv[4 + script_count :]

# `if:` expressions that can only widen when a step runs. Compared after
# stripping `${{ }}` and whitespace.
PERMISSIVE_CONDITIONS = {"always()", "!cancelled()", "success() || failure()"}
APPROVED_RUN_SHELLS = {
    None,
    "bash",
    "/bin/bash --noprofile --norc -e -o pipefail {0}",
    "/usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin /bin/bash --noprofile --norc -e -o pipefail {0}",
}


def normalize_condition(value):
    text = value.strip()
    if text.startswith("${{") and text.endswith("}}"):
        text = text[3:-2]
    return " ".join(text.split())


def execution_rejection(
    workflow_default_shell,
    job_if,
    job_continue_on_error,
    job_default_shell,
    step,
):
    if job_if is not None and normalize_condition(job_if) not in PERMISSIVE_CONDITIONS:
        return f"job guarded by `if: {job_if}`"
    if step["if"] is not None and normalize_condition(step["if"]) not in PERMISSIVE_CONDITIONS:
        return f"step guarded by `if: {step['if']}`"
    if job_continue_on_error not in (None, "false"):
        return f"job continue-on-error is {job_continue_on_error}"
    if step["continue-on-error"] not in (None, "false"):
        return f"step continue-on-error is {step['continue-on-error']}"
    effective_shell = (
        step["shell"]
        if step["shell"] is not None
        else job_default_shell
        if job_default_shell is not None
        else workflow_default_shell
    )
    if effective_shell not in APPROVED_RUN_SHELLS:
        return f"run shell is not approved: {effective_shell}"
    return None


def indent_of(line):
    return len(line) - len(line.lstrip(" "))


def is_skippable(line):
    stripped = line.strip()
    return not stripped or stripped.startswith("#")


def split_key(line):
    """Return (key, inline_value) for `key: value`, else None."""
    stripped = line.strip()
    if ":" not in stripped:
        return None
    key, _, value = stripped.partition(":")
    key = key.strip()
    if not key or " " in key or key.startswith("-"):
        return None
    return key, value.strip()


def collect_block(lines, start, parent_indent):
    """Consume a block scalar body: every line indented past parent_indent.

    SHELL comments inside the body are dropped. This gate's whole claim is that a
    script only counts as wired when a workflow really invokes it, and its own
    header lists "a mention inside a `#` comment" as the first thing it rejects.
    Without this filter that was true only of YAML-level comments: commenting the
    invocation out INSIDE a `run: |` body still counted as wired and the gate
    exited 0 -- which is exactly how somebody disables a step while keeping a
    required check green, i.e. the case most worth catching. Verified both ways
    by the review that found it.
    """
    body = []
    index = start
    while index < len(lines):
        line = lines[index]
        if not line.strip():
            body.append("")
            index += 1
            continue
        if indent_of(line) <= parent_indent:
            break
        stripped = line.strip()
        if stripped.startswith("#"):
            index += 1
            continue
        body.append(stripped)
        index += 1
    return "\n".join(body), index


def collect_default_run_shell(lines, start, parent_indent):
    shell = None
    index = start
    while index < len(lines):
        line = lines[index]
        if is_skippable(line):
            index += 1
            continue
        line_indent = indent_of(line)
        if line_indent <= parent_indent:
            break
        parsed = split_key(line)
        if line_indent == parent_indent + 2 and parsed and parsed[0] == "run":
            index += 1
            while index < len(lines):
                nested = lines[index]
                if is_skippable(nested):
                    index += 1
                    continue
                nested_indent = indent_of(nested)
                if nested_indent <= parent_indent + 2:
                    break
                nested_parsed = split_key(nested)
                if (
                    nested_indent == parent_indent + 4
                    and nested_parsed
                    and nested_parsed[0] == "shell"
                ):
                    shell = nested_parsed[1]
                index += 1
            continue
        index += 1
    return shell, index


def parse_workflow(path, text):
    """Structural scan of the block-mapping subset GitHub workflows use.

    Returns (has_trigger, [(job_name, job_if, [step_dict, ...]), ...]).
    """
    lines = text.split("\n")

    has_trigger = False
    workflow_default_shell = None
    jobs = []

    index = 0
    while index < len(lines):
        line = lines[index]
        if is_skippable(line) or indent_of(line) != 0:
            index += 1
            continue
        parsed = split_key(line)
        if parsed is None:
            index += 1
            continue
        key, _ = parsed
        # YAML 1.1 folds bare `on` to a boolean; the text form is what is on disk.
        if key in ("on", "true", "True"):
            has_trigger = True
            index += 1
            continue
        if key == "defaults":
            workflow_default_shell, index = collect_default_run_shell(lines, index + 1, 0)
            continue
        if key != "jobs":
            index += 1
            continue

        index += 1
        while index < len(lines):
            line = lines[index]
            if is_skippable(line):
                index += 1
                continue
            if indent_of(line) < 2:
                break
            if indent_of(line) != 2:
                index += 1
                continue
            parsed = split_key(line)
            if parsed is None:
                index += 1
                continue
            job_name = parsed[0]
            job_if = None
            job_continue_on_error = None
            job_default_shell = None
            steps = []
            index += 1

            while index < len(lines):
                line = lines[index]
                if is_skippable(line):
                    index += 1
                    continue
                if indent_of(line) <= 2:
                    break
                if indent_of(line) != 4:
                    index += 1
                    continue
                parsed = split_key(line)
                if parsed is None:
                    index += 1
                    continue
                job_key, job_value = parsed
                if job_key == "if":
                    job_if = job_value
                    index += 1
                    continue
                if job_key == "continue-on-error":
                    job_continue_on_error = job_value
                    index += 1
                    continue
                if job_key == "defaults":
                    job_default_shell, index = collect_default_run_shell(
                        lines, index + 1, 4
                    )
                    continue
                if job_key != "steps":
                    index += 1
                    continue

                index += 1
                current = None
                # Indent at which THIS step's own keys sit. Anything deeper
                # belongs to a nested mapping (`with:`, `env:`) and must not be
                # read as a step key -- `with: name:` on an upload-artifact step
                # otherwise overwrites the step name, which is exactly what the
                # PyYAML cross-check caught before this landed.
                step_key_indent = None
                while index < len(lines):
                    line = lines[index]
                    if is_skippable(line):
                        index += 1
                        continue
                    line_indent = indent_of(line)
                    if line_indent <= 4:
                        break
                    stripped = line.lstrip(" ")
                    if stripped.startswith("- "):
                        current = {
                            "name": None,
                            "if": None,
                            "run": None,
                            "shell": None,
                            "continue-on-error": None,
                        }
                        steps.append(current)
                        # Re-indent `- key: value` to `  key: value` so every
                        # step key sits at one indent level.
                        line = " " * line_indent + "  " + stripped[2:]
                        line_indent += 2
                        step_key_indent = line_indent
                        stripped = line.lstrip(" ")
                    if current is None or line_indent != step_key_indent:
                        index += 1
                        continue
                    parsed = split_key(line)
                    if parsed is None:
                        index += 1
                        continue
                    step_key, step_value = parsed
                    if step_key not in (
                        "name", "if", "run", "shell", "continue-on-error"
                    ):
                        index += 1
                        continue
                    if step_value in ("|", "|-", "|+", ">", ">-", ">+", ""):
                        body, index = collect_block(lines, index + 1, line_indent)
                        current[step_key] = body
                        continue
                    current[step_key] = step_value
                    index += 1

            jobs.append(
                (
                    job_name,
                    job_if,
                    job_continue_on_error,
                    job_default_shell,
                    steps,
                )
            )

    return has_trigger, workflow_default_shell, jobs


ROOT = pathlib.Path.cwd().resolve()
EXPECTED_BASE = "ff762236a216f44d26da90d7b3fe7eeecc3d178d"
EXPECTED_UNWIRED = {"tools/check-collective-hypothesis-graph.sh"}
DEPENDENCY_CHECKER = "tools/check-witness-dependency-closure.sh"
PHASE285_WORKFLOW_PATH = ".github/workflows/ci.yml"
EXPECTED_PHASE285_WORKFLOW_POLICY_SHA256 = "cf25b5b194a3ce7003db3262dbdfd5f87dbb780bd89b35526023ea45c05395ec"
EXPECTED_PHASE285_WORKSPACE_JOB_SHA256 = "c19f04072a3a1024e886e21f911b71239eec160837ff9e8740903179b5335271"
EXPECTED_PHASE285_JOB_SHA256 = "b819ea773305a4de15ec498ad25fdeec0974c078089a4eeb2d47d6e6276a0665"
EXPECTED_FMT_JOB_SHA256 = "8320dc038e322c8b2cdbe432b6d77ca825e44aa94913dcf13d7c91bda52a0923"
EXPECTED_WORKSPACE_RUN_SHA256 = "81a78f526e8ca1fb8b5fde286aaa33db1e363fbe5da76e58ae9b9eaef6f93d67"
EXPECTED_ASSURANCE_RUN_SHA256 = "8ed78d3ca4c43679ba894d60a1f00d2caf301df053409d093b2c7e34ffa77562"
EXPECTED_FMT_RUN_SHA256 = "b6e19c16e0d5f97094745b63c78c4f15238111c4de91b081bba774a71abff1e8"
REQUIRED_PHASE285 = [
    "cargo test --workspace --locked --offline",
    "run_assured /bin/bash tools/check-phase285-witness-integrity.sh --integrity-self-test",
    "run_assured /bin/bash tools/check-phase285-witness-integrity.sh response-failure-wire",
    "run_assured /bin/bash tools/check-phase285-witness-integrity.sh candidate-verifier",
    "run_assured /bin/bash tools/check-phase285-witness-integrity.sh protocol-checkpoint",
    "run_assured /bin/bash tools/check-phase285-witness-integrity.sh atomic-store-contract",
    "run_assured /bin/bash tools/check-phase285-witness-integrity.sh in-memory-differential",
    "run_assured /bin/bash tools/check-phase285-witness-integrity.sh typed-proxy",
    "run_assured /bin/bash tools/check-phase285-witness-integrity.sh transport-layering",
    "run_assured /bin/bash tools/check-witness-dependency-closure.sh --library-only",
    "run_assured /bin/bash tools/check-witness-dependency-closure.sh --current-targets",
    "run_assured /bin/bash tools/with-nats-jetstream.sh --relay-service-checkpoint /usr/bin/env PHASE285_CONNZ_CURL_BIN=\"$PHASE285_CONNZ_CURL_BIN\" PHASE285_SERVICE_CHECKPOINT_TREE=\"$PHASE285_CANDIDATE_TREE\" PHASE285_WITNESS_INTEGRITY_LAUNCHER_SHA256=\"$PHASE285_WITNESS_INTEGRITY_LAUNCHER_SHA256\" PHASE285_WITNESS_INTEGRITY_MANIFEST_SHA256=\"$PHASE285_WITNESS_INTEGRITY_MANIFEST_SHA256\" /bin/bash tools/check-phase285-witness-integrity.sh --focused-service-checkpoint-ci-harness",
    "run_assured \"$PHASE285_CARGO\" clippy -p swarm-governance -p swarm-governance-witness --all-targets --all-features --locked --offline -- -D warnings",
    "cargo fmt --all -- --check",
    "run_assured \"$PHASE285_SHELLCHECK\" --norc tools/check-gates-wired.sh tools/check-negative-registry.sh tools/check-phase285-witness-conformance.sh tools/check-phase285-witness-integrity.sh tools/check-witness-dependency-closure.sh tools/with-nats-jetstream.sh",
    "run_assured \"$PHASE285_ACTIONLINT\" .github/workflows/ci.yml",
]
REQUIRED_PHASE285_RUN_BLOCKS = [
    ("workspace-tests", EXPECTED_WORKSPACE_RUN_SHA256),
    ("assurance-monolith", EXPECTED_ASSURANCE_RUN_SHA256),
    ("format", EXPECTED_FMT_RUN_SHA256),
]
COMMAND_MUTATION_KINDS = (
    "deletion",
    "guarded",
    "duplication",
    "renamed",
    "replacement",
    "shell-if-false",
    "heredoc-burial",
    "custom-shell-noop",
    "continue-on-error",
    "job-continue-on-error",
    "job-default-shell-noop",
    "workflow-default-shell-noop",
)
WORKFLOW_CONTRACT_MUTATION_KINDS = (
    "trigger-path-restriction",
    "permission-omission",
    "permission-escalation",
    "top-bash-env-addition",
    "top-pythonpath-addition",
    "workspace-runner-substitution",
    "workspace-mutable-action-ref",
    "workspace-test-guard",
    "workspace-target-dir-checkout",
    "workspace-added-later-step",
    "runner-substitution",
    "preceding-path-writer",
    "phase-mutable-action-ref",
    "assurance-source-hydration-omission",
    "assurance-source-hydration-target-checkout",
    "assurance-target-dir-checkout",
    "assurance-inventory-omission",
    "assurance-added-later-step",
    "assurance-git-replace-env-omission",
    "assurance-baseline-redefinition",
    "assurance-tool-rebinding",
    "assurance-user-path-precedence",
    "assurance-tool-verifier-omission",
    "assurance-rustup-actual-binding-omission",
    "assurance-connz-curl-binding-omission",
    "assurance-connz-curl-binding-substitution",
    "assurance-run-wrapper-omission",
    "assurance-expected-status-wrapper-omission",
    "assurance-integrity-root-recompute",
    "assurance-git-index-write",
    "assurance-git-ref-write",
    "assurance-main-invocation-omission",
    "assurance-cargo-env-injection",
    "assurance-target-reuse",
    "assurance-target-precreation",
    "assurance-target-cleanup-omission",
    "assurance-target-rename-decoy",
    "assurance-cargo-source-mutation",
    "assurance-sysroot-mutation",
    "assurance-ancestor-config-mutation",
    "fmt-runner-substitution",
    "fmt-added-step",
    "fmt-continue-on-error",
    "fmt-mutable-action-ref",
)
REQUIRED_PHASE285_CHECKERS = [
    "tools/check-phase285-witness-conformance.sh",
    "tools/check-phase285-deployment.sh",
    "tools/check-phase285-closure.sh",
    "tools/check-phase285-evidence.sh",
    "tools/check-phase285-plan-schema.sh",
    "tools/check-phase285-governance-persistence.sh",
]


class DifferentialFailure(Exception):
    pass


class ScratchBoundaryFailure(Exception):
    pass


class ScratchExternalProcessFailure(Exception):
    pass


def evaluate(subject_scripts, workflow_sources):
    """Run the normal structural parser over one immutable subject snapshot."""
    errors = []
    parsed_workflows = []
    total_run_steps = 0
    if not subject_scripts:
        errors.append(
            "no tools/check-*.sh or tools/verify-*.sh found; refusing to pass silently"
        )
    if not workflow_sources:
        errors.append("no .github/workflows/*.yml found; refusing to pass silently")
    for path in sorted(workflow_sources):
        has_trigger, workflow_default_shell, jobs = parse_workflow(
            path, workflow_sources[path]
        )
        if not jobs:
            errors.append(f"{path} parsed to zero jobs; refusing to pass silently")
            continue
        if not has_trigger:
            errors.append(
                f"note: {path} declares no `on:` trigger; its jobs do not count as wired"
            )
        total_run_steps += sum(
            1 for _, _, _, _, steps in jobs for step in steps if step["run"]
        )
        parsed_workflows.append((path, has_trigger, workflow_default_shell, jobs))
    if total_run_steps == 0:
        errors.append(
            "parsed zero `run:` steps across all workflows; the scanner is broken "
            "and would report every gate as unwired"
        )

    wiring = {}
    rejected_wiring = {}
    for script in sorted(subject_scripts):
        wired_at = []
        rejected = []
        for path, has_trigger, workflow_default_shell, jobs in parsed_workflows:
            for (
                job_name,
                job_if,
                job_continue_on_error,
                job_default_shell,
                steps,
            ) in jobs:
                for step in steps:
                    run = step["run"]
                    if not run or script not in run:
                        continue
                    where = f"{path}:{job_name}:{step['name'] or '<unnamed step>'}"
                    if not has_trigger:
                        rejected.append(f"{where} (workflow has no `on:` trigger)")
                        continue
                    rejection = execution_rejection(
                        workflow_default_shell,
                        job_if,
                        job_continue_on_error,
                        job_default_shell,
                        step,
                    )
                    if rejection is not None:
                        rejected.append(f"{where} ({rejection})")
                        continue
                    wired_at.append(where)
        wiring[script] = wired_at
        rejected_wiring[script] = rejected

    return {
        "errors": errors,
        "parsed_workflows": parsed_workflows,
        "total_run_steps": total_run_steps,
        "wiring": wiring,
        "rejected": rejected_wiring,
        "unwired": {script for script, locations in wiring.items() if not locations},
        "workflow_sources": dict(workflow_sources),
    }


def render_normal(result):
    for error in result["errors"]:
        if error.startswith("note:"):
            print(error)
        else:
            print(f"::error::{error}", file=sys.stderr)
    print(
        f"parsed {result['total_run_steps']} run-steps across "
        f"{len(result['parsed_workflows'])} workflow(s)"
    )
    for script in sorted(result["wiring"]):
        locations = result["wiring"][script]
        if locations:
            print(f"wired: {script}")
            for where in locations:
                print(f"    {where}")
            continue
        if script in EXPECTED_UNWIRED:
            print(f"parked-expected: {script} owner=Phase286")
            continue
        print(f"::error::{script} is invoked by no workflow step", file=sys.stderr)
        rejected = result["rejected"][script]
        for where in rejected:
            print(f"::error::  rejected: {where}", file=sys.stderr)
        if not rejected:
            print(
                f"::error::  no `run:` command in .github/workflows/ mentions {script}",
                file=sys.stderr,
            )


def git_bytes(*arguments):
    environment = os.environ.copy()
    environment["GIT_OPTIONAL_LOCKS"] = "0"
    environment["GIT_NO_REPLACE_OBJECTS"] = "1"
    result = subprocess.run(
        ["git", *arguments],
        cwd=ROOT,
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode:
        raise DifferentialFailure(
            f"git {' '.join(arguments)} failed: "
            f"{result.stderr.decode(errors='replace').strip()}"
        )
    return result.stdout


def path_within(child, ancestor):
    try:
        child.relative_to(ancestor)
        return True
    except ValueError:
        return False


def git_boundaries():
    return [
        ROOT,
        pathlib.Path(
            git_bytes("rev-parse", "--path-format=absolute", "--git-dir")
            .decode()
            .strip()
        ).resolve(strict=True),
        pathlib.Path(
            git_bytes("rev-parse", "--path-format=absolute", "--git-common-dir")
            .decode()
            .strip()
        ).resolve(strict=True),
    ]


@contextlib.contextmanager
def confined_scratch(prefix, parent=None, boundaries=None):
    resolved_boundaries = tuple(
        git_boundaries() if boundaries is None else boundaries
    )
    if not resolved_boundaries or any(
        not boundary.is_absolute() or boundary != boundary.resolve(strict=True)
        for boundary in resolved_boundaries
    ):
        raise DifferentialFailure("scratch boundaries are not immutable absolute paths")
    if parent is not None:
        requested_parent_value = parent
    elif "TMPDIR" in os.environ:
        requested_parent_value = os.environ["TMPDIR"]
    else:
        requested_parent_value = tempfile.gettempdir()
    requested_parent = pathlib.Path(requested_parent_value).resolve(strict=True)
    if any(
        requested_parent == boundary or path_within(requested_parent, boundary)
        for boundary in resolved_boundaries
    ):
        raise ScratchBoundaryFailure(
            f"scratch parent refusal before create: {requested_parent}"
        )
    scratch = pathlib.Path(
        tempfile.mkdtemp(prefix=f"{prefix}.", dir=requested_parent)
    ).resolve(strict=True)
    if any(scratch.iterdir()):
        shutil.rmtree(scratch)
        if scratch.exists():
            raise DifferentialFailure("new scratch was nonempty and cleanup failed")
        raise DifferentialFailure("new scratch directory was not empty")
    if any(
        path_within(scratch, boundary) or path_within(boundary, scratch)
        for boundary in resolved_boundaries
    ):
        scratch.rmdir()
        if scratch.exists():
            raise DifferentialFailure("overlapping scratch cleanup failed")
        raise ScratchBoundaryFailure("scratch overlaps subject or Git boundary")
    try:
        yield scratch
    finally:
        shutil.rmtree(scratch)
        if scratch.exists():
            raise DifferentialFailure("scratch cleanup left its target behind")


def scratch_hostile_controls():
    rejected = 0
    external_process_mutation_killed = 0
    post_hostile_positive = 0
    boundaries = tuple(git_boundaries())
    original_tempfile_tempdir = tempfile.tempdir
    tempfile.tempdir = None

    def reject_external_process(*_arguments, **_keywords):
        raise ScratchExternalProcessFailure(
            "external process attempted after hostile TMPDIR assignment"
        )

    for boundary in boundaries:
        before_children = {entry.name for entry in boundary.iterdir()}
        had_tmpdir = "TMPDIR" in os.environ
        original_tmpdir = os.environ.get("TMPDIR")
        original_subprocess_run = subprocess.run
        try:
            os.environ["TMPDIR"] = str(boundary)
            subprocess.run = reject_external_process
            with confined_scratch(
                "phase285-wiring-hostile", boundaries=boundaries
            ):
                pass
        except ScratchBoundaryFailure:
            rejected += 1
        else:
            raise DifferentialFailure(
                f"hostile TMPDIR boundary was accepted: {boundary}"
            )
        finally:
            subprocess.run = original_subprocess_run
            if had_tmpdir:
                os.environ["TMPDIR"] = original_tmpdir
            else:
                os.environ.pop("TMPDIR", None)
        after_children = {entry.name for entry in boundary.iterdir()}
        if after_children != before_children:
            raise DifferentialFailure(
                "hostile TMPDIR refusal created a child path: "
                f"boundary={boundary} added={sorted(after_children - before_children)} "
                f"removed={sorted(before_children - after_children)}"
            )
    boundary = boundaries[0]
    before_children = {entry.name for entry in boundary.iterdir()}
    had_tmpdir = "TMPDIR" in os.environ
    original_tmpdir = os.environ.get("TMPDIR")
    original_subprocess_run = subprocess.run
    try:
        os.environ["TMPDIR"] = str(boundary)
        subprocess.run = reject_external_process
        with confined_scratch("phase285-wiring-hostile-omission"):
            pass
    except ScratchExternalProcessFailure:
        external_process_mutation_killed = 1
    else:
        raise DifferentialFailure(
            "hostile scratch boundary omission did not attempt the blocked resolver"
        )
    finally:
        subprocess.run = original_subprocess_run
        if had_tmpdir:
            os.environ["TMPDIR"] = original_tmpdir
        else:
            os.environ.pop("TMPDIR", None)
    after_children = {entry.name for entry in boundary.iterdir()}
    if after_children != before_children:
        raise DifferentialFailure(
            "hostile resolver-omission control created a boundary child"
        )
    if tempfile.tempdir is not None:
        raise DifferentialFailure("hostile TMPDIR poisoned tempfile's cached default")
    had_tmpdir = "TMPDIR" in os.environ
    original_tmpdir = os.environ.get("TMPDIR")
    os.environ.pop("TMPDIR", None)
    ordinary_scratch = None
    try:
        with confined_scratch(
            "phase285-wiring-post-hostile", boundaries=boundaries
        ) as scratch:
            ordinary_scratch = scratch
            if any(scratch.iterdir()):
                raise DifferentialFailure("post-hostile scratch was not empty")
            post_hostile_positive = 1
    finally:
        if had_tmpdir:
            os.environ["TMPDIR"] = original_tmpdir
        else:
            os.environ.pop("TMPDIR", None)
        tempfile.tempdir = original_tempfile_tempdir
    if ordinary_scratch is None or ordinary_scratch.exists():
        raise DifferentialFailure("post-hostile scratch cleanup failed")
    if rejected != 3:
        raise DifferentialFailure(f"hostile scratch control count drifted: {rejected}")
    if external_process_mutation_killed != 1:
        raise DifferentialFailure("hostile external-process mutation survived")
    if post_hostile_positive != 1:
        raise DifferentialFailure("post-hostile ordinary scratch did not run")
    print(
        f"phase285_scratch_self_test site=gates boundaries={rejected} "
        "child_paths_created=0 external_process_mutation=1 "
        "post_hostile_positive=1 passed=1"
    )


def eligible_script(path):
    return fnmatch.fnmatch(path, "tools/check-*.sh") or fnmatch.fnmatch(
        path, "tools/verify-*.sh"
    )


def eligible_workflow(path):
    return path.startswith(".github/workflows/") and path.endswith((".yml", ".yaml"))


def load_base(commit):
    if commit != EXPECTED_BASE:
        raise DifferentialFailure(
            f"base commit mismatch: expected {EXPECTED_BASE}, observed {commit}"
        )
    resolved = git_bytes("rev-parse", "--verify", f"{commit}^{{commit}}").decode().strip()
    if resolved != EXPECTED_BASE:
        raise DifferentialFailure(
            f"base object mismatch: expected {EXPECTED_BASE}, resolved {resolved}"
        )
    names = git_bytes(
        "ls-tree", "-r", "-z", "--name-only", commit, "--", "tools", ".github/workflows"
    ).decode().split("\0")
    base_scripts = sorted(path for path in names if path and eligible_script(path))
    base_workflows = {}
    for path in sorted(path for path in names if path and eligible_workflow(path)):
        base_workflows[path] = git_bytes("cat-file", "blob", f"{commit}:{path}").decode()
    return base_scripts, base_workflows


def candidate_workflow_sources():
    return {
        path: (ROOT / path).read_text(encoding="utf-8")
        for path in sorted(workflows)
    }


def valid_run_texts(result):
    runs = []
    for _, has_trigger, workflow_default_shell, jobs in result["parsed_workflows"]:
        if not has_trigger:
            continue
        for _, job_if, job_continue_on_error, job_default_shell, steps in jobs:
            for step in steps:
                if execution_rejection(
                    workflow_default_shell,
                    job_if,
                    job_continue_on_error,
                    job_default_shell,
                    step,
                ) is not None:
                    continue
                if step["run"]:
                    runs.append(step["run"])
    return runs


def exact_command_counts(result):
    counts = {command: 0 for command in REQUIRED_PHASE285}
    for run in valid_run_texts(result):
        for line in run.splitlines():
            command = line.strip()
            if command in counts:
                counts[command] += 1
    return counts


def canonical_run_block_counts(result):
    runs = [hashlib.sha256(run.encode()).hexdigest() for run in valid_run_texts(result)]
    return {
        label: runs.count(expected_digest)
        for label, expected_digest in REQUIRED_PHASE285_RUN_BLOCKS
    }


def validate_phase285_raw_workflow_contract(result):
    source = result["workflow_sources"].get(PHASE285_WORKFLOW_PATH)
    if source is None:
        raise DifferentialFailure("Phase 285 workflow contract is absent")
    jobs = list(re.finditer(r"^jobs:\s*\n", source, re.M))
    if len(jobs) != 1:
        raise DifferentialFailure("Phase 285 workflow contract anchors differ")

    def raw_job(job_name, diagnostic):
        matches = list(
            re.finditer(rf"^  {re.escape(job_name)}:\s*\n", source, re.M)
        )
        if len(matches) != 1 or matches[0].start() < jobs[0].end():
            raise DifferentialFailure(f"{diagnostic} contract anchor differs")
        adjacent = re.search(
            r"^  [A-Za-z0-9_-]+:\s*\n",
            source[matches[0].end() :],
            re.M,
        )
        end = (
            matches[0].end() + adjacent.start()
            if adjacent is not None
            else len(source)
        )
        return source[matches[0].start() : end].encode()

    policy = source[: jobs[0].end()].encode()
    workspace_job = raw_job("phase285-workspace-tests", "Phase 285 workspace job")
    job = raw_job("phase285-wave0-contract", "Phase 285 job execution")
    fmt_job = raw_job("fmt", "Phase 285 fmt job")
    if hashlib.sha256(policy).hexdigest() != EXPECTED_PHASE285_WORKFLOW_POLICY_SHA256:
        raise DifferentialFailure("Phase 285 workflow policy contract mismatch")
    if hashlib.sha256(workspace_job).hexdigest() != EXPECTED_PHASE285_WORKSPACE_JOB_SHA256:
        raise DifferentialFailure("Phase 285 workspace job contract mismatch")
    if hashlib.sha256(job).hexdigest() != EXPECTED_PHASE285_JOB_SHA256:
        raise DifferentialFailure("Phase 285 job execution contract mismatch")
    if hashlib.sha256(fmt_job).hexdigest() != EXPECTED_FMT_JOB_SHA256:
        raise DifferentialFailure("Phase 285 fmt job contract mismatch")
    policy_text = policy.decode()
    workspace_text = workspace_job.decode()
    job_text = job.decode()
    fmt_text = fmt_job.decode()
    policy_fragments = (
        "name: CI\n",
        "on:\n  push:\n    branches:\n      - main\n  pull_request:\n    branches:\n      - main\n",
        "permissions:\n  contents: read\n",
        "env:\n  CARGO_TERM_COLOR: always\n  CARGO_TARGET_DIR: ${{ github.workspace }}/target/ci\n",
    )
    workspace_fragments = (
        "  phase285-workspace-tests:\n",
        "    name: phase285-workspace-tests (${{ github.sha }})\n",
        "    runs-on: ubuntu-24.04\n",
        "    defaults:\n      run:\n        shell: /bin/bash --noprofile --norc -e -o pipefail {0}\n        working-directory: .\n",
        "        uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683\n",
        "          persist-credentials: false\n",
        "        uses: actions/cache@0057852bfaa89a56745cba8c7296529d2fc39830\n",
        "        uses: dtolnay/rust-toolchain@4cda84d5c5c54efe2404f9d843567869ab1699d4\n",
        "          toolchain: stable\n",
        "        run: cargo fetch --locked\n",
        "      - name: Run ordinary workspace tests as the final candidate step\n",
        "          CARGO_TARGET_DIR: ${{ runner.temp }}/phase285-workspace-tests-target\n          CARGO_INCREMENTAL: \"0\"\n",
        "        run: |\n          cargo test --workspace --locked --offline\n",
    )
    job_fragments = (
        "  phase285-wave0-contract:\n",
        "    name: phase285-wave0-contract (${{ github.sha }})\n",
        "    runs-on: ubuntu-24.04\n",
        "    # This is a CI self-consistency boundary, not a hostile sandbox. Intentional\n",
        "    # child invocation, and compromised hosted toolchain/cache infrastructure\n",
        "    defaults:\n      run:\n        shell: /bin/bash --noprofile --norc -e -o pipefail {0}\n        working-directory: .\n",
        "        uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683\n",
        "          persist-credentials: false\n",
        "        uses: actions/cache@0057852bfaa89a56745cba8c7296529d2fc39830\n",
        "        uses: dtolnay/rust-toolchain@4cda84d5c5c54efe2404f9d843567869ab1699d4\n",
        "          toolchain: stable\n          components: clippy\n",
        "      - name: Hydrate the complete locked Cargo source closure\n",
        "          CARGO_TARGET_DIR: ${{ runner.temp }}/phase285-source-hydration-target\n          CARGO_INCREMENTAL: \"0\"\n",
        "          cargo fetch --locked\n          cargo test -p swarm-governance -p swarm-governance-witness --all-targets --all-features --locked --no-run\n",
        "          target = pathlib.Path(sys.argv[1])\n          runner_temp = pathlib.Path(sys.argv[2]).resolve(strict=True)\n",
        "              or target.name != \"phase285-source-hydration-target\"\n",
        "          shutil.rmtree(target)\n          if os.path.lexists(target):\n              raise SystemExit(\"phase285_source_hydration[target-residue]\")\n",
        "          print(\"phase285_source_hydration closure=governance-witness-all-targets-all-features target_residue=0 passed=1\")\n",
        "        run: go install github.com/rhysd/actionlint/cmd/actionlint@v1.7.7\n",
        "      - name: Run the isolated Phase 285 assurance monolith as the final candidate step\n",
        "          CARGO_TARGET_DIR: ${{ runner.temp }}/phase285-assurance-target\n          CARGO_INCREMENTAL: \"0\"\n",
        "          GIT_NO_REPLACE_OBJECTS: \"1\"\n          GIT_OPTIONAL_LOCKS: \"0\"\n",
        "        run: |\n          phase285_assurance_main() {\n",
        "          set -euo pipefail\n",
        "          unset BASH_ENV ENV CDPATH PYTHONPATH PYTHONHOME PYTHONSTARTUP PYTHONINSPECT\n",
        "          unset RUSTFLAGS RUSTDOCFLAGS RUSTC_WRAPPER RUSTC_WORKSPACE_WRAPPER\n",
        "          unset SHELLCHECK_OPTS CLIPPY_CONF_DIR\n",
        "          unset DOCKER_HOST DOCKER_CONTEXT DOCKER_CONFIG\n",
        "          done < <(compgen -A variable GIT_)\n",
        "          GIT_NO_REPLACE_OBJECTS=1\n          GIT_OPTIONAL_LOCKS=0\n",
        "          GIT_CONFIG_GLOBAL=/dev/null\n          GIT_CONFIG_SYSTEM=/dev/null\n          GIT_CONFIG_NOSYSTEM=1\n          GIT_ATTR_NOSYSTEM=1\n",
        "          DOCKER_CONFIG=\"$PHASE285_DOCKER_CONFIG\"\n",
        "          /usr/bin/python3 -I - \"$PHASE285_TARGET_ROOT\" \"$DOCKER_CONFIG\" <<'PY'\n",
        "          PHASE285_RUSTUP=\"$(command -v rustup)\"\n",
        "          PHASE285_CONNZ_CURL_BIN=/usr/bin/curl\n          export PHASE285_CONNZ_CURL_BIN\n",
        "          PHASE285_CARGO=\"$(\"$PHASE285_RUSTUP\" which cargo)\"\n          PHASE285_RUSTC=\"$(\"$PHASE285_RUSTUP\" which rustc)\"\n",
        "          PHASE285_CARGO_CLIPPY=\"$(\"$PHASE285_RUSTUP\" which cargo-clippy)\"\n          PHASE285_CLIPPY_DRIVER=\"$(\"$PHASE285_RUSTUP\" which clippy-driver)\"\n",
        "          PHASE285_SYSROOT=\"$(\"$PHASE285_RUSTC\" --print sysroot)\"\n",
        "          PHASE285_ACTIONLINT=\"$($PHASE285_GO env GOPATH)/bin/actionlint\"\n",
        "          capture_candidate_baseline() {\n            /usr/bin/python3 -I - \"$GITHUB_SHA\" \"$PHASE285_CARGO_HOME\" \"$PHASE285_DOCKER_CONFIG\" \"$PHASE285_TARGET_ROOT\" \"$PHASE285_SYSROOT\" \\\n",
        "              curl \"$PHASE285_CONNZ_CURL_BIN\" \\\n",
        "[\"/usr/bin/git\", \"rev-parse\", \"--verify\", \"HEAD\"]",
        "[\"/usr/bin/git\", \"ls-tree\", \"-rz\", \"--full-tree\", expected_sha]",
        "                  \"git\": git_inventory,\n",
        "                  \"cargo_controls\": cargo_controls,\n",
        "                  \"cargo_ancestor_controls\": cargo_ancestor_controls,\n",
        "                  \"cargo_source_trees\": cargo_source_trees,\n",
        "                  \"docker_config_inventory\": docker_config_inventory,\n",
        "                  \"target_root_identity\": [\n",
        "                  \"sysroot\": sysroot_control,\n",
        "                  \"tools\": tools,\n",
        "          readonly PATH RUSTC RUSTFMT CLIPPY_DRIVER CLIPPY_CONF_DIR PHASE285_BASH PHASE285_GIT PHASE285_PYTHON PHASE285_SHASUM PHASE285_AWK PHASE285_MKTEMP PHASE285_CONNZ_CURL_BIN PHASE285_RUSTUP PHASE285_CARGO PHASE285_RUSTC PHASE285_RUSTFMT PHASE285_CARGO_CLIPPY PHASE285_CLIPPY_DRIVER PHASE285_SYSROOT PHASE285_GO PHASE285_SHELLCHECK PHASE285_DOCKER PHASE285_ACTIONLINT PHASE285_CANDIDATE_TREE PHASE285_CANDIDATE_BASELINE PHASE285_CANDIDATE_BASELINE_SHA256\n",
        "          CLIPPY_CONF_DIR=\"$PWD\"\n",
        "            /usr/bin/python3 -I - \"$PHASE285_CANDIDATE_BASELINE_SHA256\" \"$GITHUB_SHA\" \"$PHASE285_ACTIVE_TARGET\" \"$PHASE285_ACTIVE_TARGET_IDENTITY\" 3<<< \"$PHASE285_CANDIDATE_BASELINE\" <<'PY'\n",
        "          for tool in baseline[\"tools\"]:\n",
        "          if recursive_inventory(git_root) != baseline[\"git\"]:\n",
        "          if observed_cargo_controls != baseline[\"cargo_controls\"]:\n",
        "          if observed_cargo_source_trees != baseline[\"cargo_source_trees\"]:\n",
        "              for source_kind in (\"git\", \"registry\"):\n",
        "                      \"missing\": sorted(set(expected_entries) - set(observed_entries))[:8],\n",
        "                      \"extra\": sorted(set(observed_entries) - set(expected_entries))[:8],\n",
        "                      \"changed\": sorted(\n",
        "                  \"candidate_inventory[cargo-source-trees:\"\n",
        "          if ancestor_cargo_controls(root) != baseline[\"cargo_ancestor_controls\"]:\n",
        "          if directory_control(sysroot_path, \"sysroot\") != baseline[\"sysroot\"]:\n",
        "          if recursive_inventory(docker_config) != baseline[\"docker_config_inventory\"]:\n",
        "              raise SystemExit(\"candidate_inventory[target-root-identity]\")\n",
        "                  raise SystemExit(\"candidate_inventory[active-target-identity]\")\n",
        "              raise SystemExit(\"candidate_inventory[inactive-target-root-not-empty]\")\n",
        "          trap verify_candidate_inventory_on_exit EXIT\n",
        "          PHASE285_WITNESS_INTEGRITY_LAUNCHER_SHA256=e59ba9f62bf126bccdf8c0d3331b54adae9e74f8fe1ee6e31d43e3dec9ca66b1\n",
        "          PHASE285_WITNESS_INTEGRITY_MANIFEST_SHA256=92f965a57aa79195acfd1b94d52e9ef09cccfdf6cc5d0381b17a76440e036bdf\n",
        "          run_assured() {\n            local command_status=0 verification_status=0 cleanup_status=0\n            verify_candidate_inventory || return $?\n            allocate_assurance_target || return $?\n",
        "            cleanup_assurance_target || cleanup_status=$?\n            if test \"$verification_status\" -ne 0; then\n              return \"$verification_status\"\n            fi\n            if test \"$cleanup_status\" -ne 0; then\n              return \"$cleanup_status\"\n            fi\n            return \"$command_status\"\n          }\n",
        "          allocate_assurance_target() {\n",
        "            created_target=\"$(\"$PHASE285_MKTEMP\" -d \"$PHASE285_TARGET_ROOT/command.XXXXXXXX\")\"\n",
        "          cleanup_assurance_target() {\n",
        "            /usr/bin/python3 -I - \"$PHASE285_TARGET_ROOT\" \"$PHASE285_ACTIVE_TARGET\" \"$PHASE285_ACTIVE_TARGET_IDENTITY\" <<'PY'\n",
        "              raise SystemExit(\"phase285_assurance_cleanup[target-identity]\")\n",
        "          shutil.rmtree(target)\n          if os.path.lexists(target):\n              raise SystemExit(\"phase285_assurance_cleanup[residue]\")\n",
        "            PHASE285_ACTIVE_TARGET=\n            PHASE285_ACTIVE_TARGET_IDENTITY=\n            unset CARGO_TARGET_DIR\n            verify_candidate_inventory\n",
        "          readonly -f phase285_assurance_main\n          phase285_assurance_main\n",
    )
    if any(policy_text.count(fragment) != 1 for fragment in policy_fragments):
        raise DifferentialFailure("Phase 285 workflow policy semantic fields mismatch")
    if any(workspace_text.count(fragment) != 1 for fragment in workspace_fragments):
        raise DifferentialFailure("Phase 285 workspace job semantic fields mismatch")
    if any(job_text.count(fragment) != 1 for fragment in job_fragments):
        raise DifferentialFailure("Phase 285 job execution semantic fields mismatch")
    fmt_fragments = (
        "    runs-on: ubuntu-latest\n",
        "        uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683\n",
        "          persist-credentials: false\n",
        "        uses: actions/cache@0057852bfaa89a56745cba8c7296529d2fc39830\n",
        "        uses: dtolnay/rust-toolchain@4cda84d5c5c54efe2404f9d843567869ab1699d4\n",
        "          toolchain: stable\n          components: rustfmt\n",
        "        run: |\n          cargo fmt --all -- --check\n",
    )
    if any(fmt_text.count(fragment) != 1 for fragment in fmt_fragments):
        raise DifferentialFailure("Phase 285 fmt job semantic fields mismatch")


def required_checker_counts(result):
    runs = valid_run_texts(result)
    counts = {}
    for checker in REQUIRED_PHASE285_CHECKERS:
        pattern = re.compile(
            rf"(?<![A-Za-z0-9_./-]){re.escape(checker)}(?![A-Za-z0-9_./-])"
        )
        counts[checker] = sum(len(pattern.findall(run)) for run in runs)
    return counts


def dependency_invocation_step_count(result):
    return sum(
        1
        for run in valid_run_texts(result)
        if any(
            line.strip().startswith(f"run_assured /bin/bash {DEPENDENCY_CHECKER} --")
            for line in run.splitlines()
        )
    )


def validate_candidate_contract(result, *, exact_unwired):
    errors = [error for error in result["errors"] if not error.startswith("note:")]
    if errors:
        raise DifferentialFailure(f"structural parser error: {errors}")
    validate_phase285_raw_workflow_contract(result)
    if exact_unwired and result["unwired"] != EXPECTED_UNWIRED:
        raise DifferentialFailure(
            f"candidate unwired set mismatch: {sorted(result['unwired'])}"
        )
    command_counts = exact_command_counts(result)
    if any(count != 1 for count in command_counts.values()):
        raise DifferentialFailure(f"Phase 285 invocation mismatch: {command_counts}")
    block_counts = canonical_run_block_counts(result)
    if any(count != 1 for count in block_counts.values()):
        raise DifferentialFailure(f"Phase 285 canonical run-block mismatch: {block_counts}")
    checker_counts = required_checker_counts(result)
    if any(count == 0 for count in checker_counts.values()):
        raise DifferentialFailure(f"Phase 285 checker wiring mismatch: {checker_counts}")
    if DEPENDENCY_CHECKER not in result["wiring"]:
        raise DifferentialFailure("witness dependency checker absent from candidate inventory")
    dependency_invocation_steps = dependency_invocation_step_count(result)
    if dependency_invocation_steps != 1:
        raise DifferentialFailure("witness dependency modes are not wired in exactly one step")
    return command_counts, checker_counts


def normal_mode_exit_code(result, phase_error):
    normal_errors = [
        error for error in result["errors"] if not error.startswith("note:")
    ]
    return int(
        bool(normal_errors)
        or result["unwired"] != EXPECTED_UNWIRED
        or phase_error is not None
    )


def validate_pair(base_snapshot, candidate_scripts, candidate_workflows):
    base_result = evaluate(*base_snapshot)
    candidate_result = evaluate(candidate_scripts, candidate_workflows)
    base_errors = [error for error in base_result["errors"] if not error.startswith("note:")]
    candidate_errors = [
        error for error in candidate_result["errors"] if not error.startswith("note:")
    ]
    if base_errors or candidate_errors:
        raise DifferentialFailure(
            f"structural parser error: base={base_errors} candidate={candidate_errors}"
        )
    if base_result["unwired"] != EXPECTED_UNWIRED:
        raise DifferentialFailure(
            f"base unwired set mismatch: {sorted(base_result['unwired'])}"
        )
    validate_candidate_contract(candidate_result, exact_unwired=True)
    return base_result, candidate_result


def subject_fingerprint():
    names = git_bytes(
        "ls-files", "-c", "-o", "--exclude-standard", "--",
        "tools/check-*.sh", "tools/verify-*.sh", ".github/workflows/*.yml",
        ".github/workflows/*.yaml",
    ).decode().splitlines()
    records = []
    for name in sorted(set(names)):
        path = ROOT / name
        stat = path.stat()
        records.append(
            (name, stat.st_mode, hashlib.sha256(path.read_bytes()).hexdigest())
        )
    status = git_bytes("status", "--porcelain=v1", "-z")
    return records, status


def command_mutation_variants(workflow_text, command):
    command_line = f"          {command}\n"
    if workflow_text.count(command) != 1 or workflow_text.count(command_line) != 1:
        raise DifferentialFailure(
            f"cannot locate one exact workflow command line for {command}"
        )
    command_offset = workflow_text.index(command_line)
    run_offset = workflow_text.rfind("\n        run:", 0, command_offset)
    if run_offset < 0:
        raise DifferentialFailure(f"cannot locate owning workflow step for {command}")
    job_matches = list(
        re.finditer(r"^  [A-Za-z0-9_-]+:\s*$", workflow_text[:command_offset], re.M)
    )
    if not job_matches:
        raise DifferentialFailure(f"cannot locate owning workflow job for {command}")
    job_insert = job_matches[-1].end() + 1
    jobs_matches = list(re.finditer(r"^jobs:\s*$", workflow_text, re.M))
    if len(jobs_matches) != 1:
        raise DifferentialFailure("workflow jobs key is missing or ambiguous")
    workflow_insert = jobs_matches[0].start()
    variants = {
        "deletion": workflow_text.replace(command_line, "", 1),
        "guarded": (
            workflow_text[: run_offset + 1]
            + "        if: false\n"
            + workflow_text[run_offset + 1 :]
        ),
        "duplication": workflow_text.replace(
            command_line, command_line + command_line, 1
        ),
        "renamed": workflow_text.replace(command, f"{command}-renamed", 1),
        "replacement": workflow_text.replace(command, f"env {command}", 1),
        "shell-if-false": workflow_text.replace(
            command_line,
            f"          if false; then\n{command_line}          fi\n",
            1,
        ),
        "heredoc-burial": workflow_text.replace(
            command_line,
            "          cat <<'PHASE285_BURIED'\n"
            f"{command_line}"
            "          PHASE285_BURIED\n",
            1,
        ),
        "custom-shell-noop": (
            workflow_text[: run_offset + 1]
            + "        shell: /bin/true {0}\n"
            + workflow_text[run_offset + 1 :]
        ),
        "continue-on-error": (
            workflow_text[: run_offset + 1]
            + "        continue-on-error: true\n"
            + workflow_text[run_offset + 1 :]
        ),
        "job-continue-on-error": (
            workflow_text[:job_insert]
            + "    continue-on-error: true\n"
            + workflow_text[job_insert:]
        ),
        "job-default-shell-noop": (
            workflow_text[:job_insert]
            + "    defaults:\n      run:\n        shell: /bin/true {0}\n"
            + workflow_text[job_insert:]
        ),
        "workflow-default-shell-noop": (
            workflow_text[:workflow_insert]
            + "defaults:\n  run:\n    shell: /bin/true {0}\n"
            + workflow_text[workflow_insert:]
        ),
    }
    if set(variants) != set(COMMAND_MUTATION_KINDS):
        raise DifferentialFailure("command mutation inventory drifted")
    return variants


def workflow_contract_mutation_variants(workflow_text):
    def job_slice(job_name):
        start_match = re.search(rf"^  {re.escape(job_name)}:\s*$", workflow_text, re.M)
        if start_match is None:
            raise DifferentialFailure(
                f"workflow contract job is absent: {job_name}"
            )
        next_match = re.search(r"^  [A-Za-z0-9_-]+:\s*$", workflow_text[start_match.end():], re.M)
        end = (
            start_match.end() + next_match.start()
            if next_match is not None
            else len(workflow_text)
        )
        return start_match.start(), end, workflow_text[start_match.start():end]

    workspace_start, workspace_end, workspace_job = job_slice("phase285-workspace-tests")
    phase_start, phase_end, phase_job = job_slice("phase285-wave0-contract")
    fmt_start, fmt_end, fmt_job = job_slice("fmt")
    workflow_anchors = {
        "trigger-path-restriction": (
            "  pull_request:\n    branches:\n      - main\n",
            "  pull_request:\n    branches:\n      - main\n    paths:\n      - 'crates/**'\n",
        ),
        "permission-omission": (
            "permissions:\n  contents: read\n\n",
            "",
        ),
        "permission-escalation": (
            "permissions:\n  contents: read\n",
            "permissions:\n  contents: write\n",
        ),
        "top-bash-env-addition": (
            "  CARGO_TARGET_DIR: ${{ github.workspace }}/target/ci\n",
            "  CARGO_TARGET_DIR: ${{ github.workspace }}/target/ci\n"
            "  BASH_ENV: /tmp/phase285-bypass\n",
        ),
        "top-pythonpath-addition": (
            "  CARGO_TARGET_DIR: ${{ github.workspace }}/target/ci\n",
            "  CARGO_TARGET_DIR: ${{ github.workspace }}/target/ci\n"
            "  PYTHONPATH: /tmp/phase285-python-bypass\n",
        ),
    }
    workspace_anchors = {
        "workspace-runner-substitution": (
            "    runs-on: ubuntu-24.04\n",
            "    runs-on: ubuntu-latest\n",
        ),
        "workspace-mutable-action-ref": (
            "        uses: dtolnay/rust-toolchain@4cda84d5c5c54efe2404f9d843567869ab1699d4\n",
            "        uses: dtolnay/rust-toolchain@stable\n",
        ),
        "workspace-test-guard": (
            "        run: |\n          cargo test --workspace --locked --offline\n",
            "        if: false\n        run: |\n          cargo test --workspace --locked --offline\n",
        ),
        "workspace-target-dir-checkout": (
            "          CARGO_TARGET_DIR: ${{ runner.temp }}/phase285-workspace-tests-target\n",
            "          CARGO_TARGET_DIR: ${{ github.workspace }}/target/workspace-mutant\n",
        ),
        "workspace-added-later-step": (
            "        run: |\n          cargo test --workspace --locked --offline\n",
            "        run: |\n          cargo test --workspace --locked --offline\n\n"
            "      - name: Run after the workspace candidate\n"
            "        run: /bin/true\n",
        ),
    }
    phase_anchors = {
        "runner-substitution": (
            "    runs-on: ubuntu-24.04\n",
            "    runs-on: ubuntu-latest\n",
        ),
        "preceding-path-writer": (
            "    steps:\n      - name: Checkout the candidate without persisted credentials\n",
            "    steps:\n"
            "      - name: Mutate PATH before assurance\n"
            "        run: echo /tmp/phase285-bypass >> \"$GITHUB_PATH\"\n\n"
            "      - name: Checkout the candidate without persisted credentials\n",
        ),
        "phase-mutable-action-ref": (
            "        uses: actions/cache@0057852bfaa89a56745cba8c7296529d2fc39830\n",
            "        uses: actions/cache@v4\n",
        ),
        "assurance-source-hydration-omission": (
            "          cargo test -p swarm-governance -p swarm-governance-witness --all-targets --all-features --locked --no-run\n",
            "          : # omitted complete source-closure hydration\n",
        ),
        "assurance-source-hydration-target-checkout": (
            "          CARGO_TARGET_DIR: ${{ runner.temp }}/phase285-source-hydration-target\n",
            "          CARGO_TARGET_DIR: ${{ github.workspace }}/target/source-hydration-mutant\n",
        ),
        "assurance-target-dir-checkout": (
            "          CARGO_TARGET_DIR: ${{ runner.temp }}/phase285-assurance-target\n",
            "          CARGO_TARGET_DIR: ${{ github.workspace }}/target/assurance-mutant\n",
        ),
        "assurance-inventory-omission": (
            "          run_assured() {\n"
            "            local command_status=0 verification_status=0 cleanup_status=0\n"
            "            verify_candidate_inventory || return $?\n",
            "          run_assured() {\n"
            "            local command_status=0 verification_status=0 cleanup_status=0\n"
            "            : # omitted pre-command inventory verification\n",
        ),
        "assurance-added-later-step": (
            "            exit 1\n          fi\n          }\n"
            "          readonly -f phase285_assurance_main\n"
            "          phase285_assurance_main\n\n  # Phase 285 runs",
            "            exit 1\n          fi\n          }\n"
            "          readonly -f phase285_assurance_main\n"
            "          phase285_assurance_main\n\n"
            "      - name: Run after the assurance monolith\n"
            "        run: /bin/true\n\n  # Phase 285 runs",
        ),
        "assurance-git-replace-env-omission": (
            "          GIT_NO_REPLACE_OBJECTS: \"1\"\n",
            "",
        ),
        "assurance-baseline-redefinition": (
            "          trap verify_candidate_inventory_on_exit EXIT\n\n          PHASE285_WITNESS_INTEGRITY_LAUNCHER_SHA256=",
            "          PHASE285_CANDIDATE_BASELINE=\"$(/usr/bin/git ls-tree -r HEAD)\"\n"
            "          trap verify_candidate_inventory_on_exit EXIT\n\n          PHASE285_WITNESS_INTEGRITY_LAUNCHER_SHA256=",
        ),
        "assurance-tool-rebinding": (
            "          run_assured \"$PHASE285_CARGO\" clippy -p swarm-governance",
            "          PHASE285_CARGO=/tmp/phase285-cargo-mutant\n"
            "          run_assured \"$PHASE285_CARGO\" clippy -p swarm-governance",
        ),
        "assurance-user-path-precedence": (
            "          PATH=\"/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin:${PHASE285_CARGO%/*}",
            "          PATH=\"${PHASE285_CARGO%/*}:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin",
        ),
        "assurance-tool-verifier-omission": (
            "          for tool in baseline[\"tools\"]:\n",
            "          for tool in []:\n",
        ),
        "assurance-rustup-actual-binding-omission": (
            "          PHASE285_RUSTC=\"$(\"$PHASE285_RUSTUP\" which rustc)\"\n",
            "          PHASE285_RUSTC=\"$(command -v rustc)\"\n",
        ),
        "assurance-connz-curl-binding-omission": (
            "          PHASE285_CONNZ_CURL_BIN=/usr/bin/curl\n"
            "          export PHASE285_CONNZ_CURL_BIN\n",
            "",
        ),
        "assurance-connz-curl-binding-substitution": (
            "          PHASE285_CONNZ_CURL_BIN=/usr/bin/curl\n",
            "          PHASE285_CONNZ_CURL_BIN=/tmp/phase285-curl-mutant\n",
        ),
        "assurance-run-wrapper-omission": (
            "          run_assured /bin/bash tools/check-phase285-witness-integrity.sh --integrity-self-test\n",
            "          /bin/bash tools/check-phase285-witness-integrity.sh --integrity-self-test\n",
        ),
        "assurance-expected-status-wrapper-omission": (
            "          elif run_assured_expect_status 127 /bin/bash tools/check-phase285-governance-persistence.sh --self-test; then\n",
            "          elif /bin/bash tools/check-phase285-governance-persistence.sh --self-test; then\n",
        ),
        "assurance-integrity-root-recompute": (
            "          PHASE285_WITNESS_INTEGRITY_LAUNCHER_SHA256=e59ba9f62bf126bccdf8c0d3331b54adae9e74f8fe1ee6e31d43e3dec9ca66b1\n",
            "          PHASE285_WITNESS_INTEGRITY_LAUNCHER_SHA256=\"$(/usr/bin/shasum -a 256 tools/check-phase285-witness-integrity.sh | /usr/bin/awk '{print $1}')\"\n",
        ),
        "assurance-git-index-write": (
            "          run_assured /bin/bash tools/check-phase285-witness-integrity.sh --integrity-self-test\n",
            "          printf phase285-mutant >> .git/index\n"
            "          run_assured /bin/bash tools/check-phase285-witness-integrity.sh --integrity-self-test\n",
        ),
        "assurance-git-ref-write": (
            "          run_assured /bin/bash tools/check-phase285-witness-integrity.sh response-failure-wire\n",
            "          /usr/bin/git update-ref refs/phase285-mutant HEAD\n"
            "          run_assured /bin/bash tools/check-phase285-witness-integrity.sh response-failure-wire\n",
        ),
        "assurance-main-invocation-omission": (
            "          readonly -f phase285_assurance_main\n          phase285_assurance_main\n",
            "          readonly -f phase285_assurance_main\n          /bin/true\n",
        ),
        "assurance-cargo-env-injection": (
            "          RUSTC_WORKSPACE_WRAPPER=\n",
            "          RUSTC_WORKSPACE_WRAPPER=\n"
            "          CARGO_REGISTRIES_CRATES_IO_INDEX=https://phase285.invalid/index\n",
        ),
        "assurance-target-reuse": (
            "            created_target=\"$(\"$PHASE285_MKTEMP\" -d \"$PHASE285_TARGET_ROOT/command.XXXXXXXX\")\"\n",
            "            created_target=\"$PHASE285_TARGET_ROOT/command.reused\"\n"
            "            /usr/bin/mkdir -p \"$created_target\"\n",
        ),
        "assurance-target-precreation": (
            "            created_target=\"$(\"$PHASE285_MKTEMP\" -d \"$PHASE285_TARGET_ROOT/command.XXXXXXXX\")\"\n",
            "            /usr/bin/mkdir \"$PHASE285_TARGET_ROOT/command.precreated\"\n"
            "            created_target=\"$PHASE285_TARGET_ROOT/command.precreated\"\n",
        ),
        "assurance-target-cleanup-omission": (
            "          run_assured() {\n"
            "            local command_status=0 verification_status=0 cleanup_status=0\n"
            "            verify_candidate_inventory || return $?\n"
            "            allocate_assurance_target || return $?\n"
            "            \"$@\" || command_status=$?\n"
            "            verify_candidate_inventory || verification_status=$?\n"
            "            cleanup_assurance_target || cleanup_status=$?\n",
            "          run_assured() {\n"
            "            local command_status=0 verification_status=0 cleanup_status=0\n"
            "            verify_candidate_inventory || return $?\n"
            "            allocate_assurance_target || return $?\n"
            "            \"$@\" || command_status=$?\n"
            "            verify_candidate_inventory || verification_status=$?\n"
            "            : # omitted assurance target cleanup\n",
        ),
        "assurance-target-rename-decoy": (
            "          run_assured /bin/bash tools/check-phase285-witness-integrity.sh response-failure-wire\n",
            "          /usr/bin/mv \"$PHASE285_ACTIVE_TARGET\" \"$PHASE285_ACTIVE_TARGET.renamed\"\n"
            "          /usr/bin/mkdir \"$PHASE285_ACTIVE_TARGET\"\n"
            "          run_assured /bin/bash tools/check-phase285-witness-integrity.sh response-failure-wire\n",
        ),
        "assurance-cargo-source-mutation": (
            "          run_assured /bin/bash tools/check-phase285-witness-integrity.sh candidate-verifier\n",
            "          printf phase285-mutant > \"$CARGO_HOME/registry/phase285-mutant\"\n"
            "          run_assured /bin/bash tools/check-phase285-witness-integrity.sh candidate-verifier\n",
        ),
        "assurance-sysroot-mutation": (
            "          run_assured /bin/bash tools/check-phase285-witness-integrity.sh protocol-checkpoint\n",
            "          printf phase285-mutant > \"$PHASE285_SYSROOT/phase285-mutant\"\n"
            "          run_assured /bin/bash tools/check-phase285-witness-integrity.sh protocol-checkpoint\n",
        ),
        "assurance-ancestor-config-mutation": (
            "          run_assured /bin/bash tools/check-phase285-witness-integrity.sh atomic-store-contract\n",
            "          /usr/bin/mkdir -p ../.cargo\n"
            "          printf '[build]' > ../.cargo/config.toml\n"
            "          run_assured /bin/bash tools/check-phase285-witness-integrity.sh atomic-store-contract\n",
        ),
    }
    fmt_anchors = {
        "fmt-runner-substitution": (
            "  fmt:\n    runs-on: ubuntu-latest\n",
            "  fmt:\n    runs-on: macos-latest\n",
        ),
        "fmt-added-step": (
            "      - name: Check formatting\n        run: |\n",
            "      - name: Mutate formatter PATH\n"
            "        run: echo /tmp/phase285-bypass >> \"$GITHUB_PATH\"\n\n"
            "      - name: Check formatting\n        run: |\n",
        ),
        "fmt-continue-on-error": (
            "      - name: Check formatting\n        run: |\n",
            "      - name: Check formatting\n"
            "        continue-on-error: true\n"
            "        run: |\n",
        ),
        "fmt-mutable-action-ref": (
            "        uses: dtolnay/rust-toolchain@4cda84d5c5c54efe2404f9d843567869ab1699d4\n",
            "        uses: dtolnay/rust-toolchain@stable\n",
        ),
    }
    variants = {}
    for label, (old, new) in workflow_anchors.items():
        if workflow_text.count(old) != 1:
            raise DifferentialFailure(
                f"workflow contract mutation anchor differs: {label}"
            )
        variants[label] = workflow_text.replace(old, new, 1)
    for label, (old, new) in workspace_anchors.items():
        if workspace_job.count(old) != 1:
            raise DifferentialFailure(
                f"workflow contract mutation anchor differs: {label}"
            )
        mutated_job = workspace_job.replace(old, new, 1)
        variants[label] = (
            workflow_text[:workspace_start]
            + mutated_job
            + workflow_text[workspace_end:]
        )
    for label, (old, new) in phase_anchors.items():
        if phase_job.count(old) != 1:
            raise DifferentialFailure(
                f"workflow contract mutation anchor differs: {label}"
            )
        mutated_job = phase_job.replace(old, new, 1)
        variants[label] = workflow_text[:phase_start] + mutated_job + workflow_text[phase_end:]
    for label, (old, new) in fmt_anchors.items():
        if fmt_job.count(old) != 1:
            raise DifferentialFailure(
                f"workflow contract mutation anchor differs: {label}"
            )
        mutated_job = fmt_job.replace(old, new, 1)
        variants[label] = workflow_text[:fmt_start] + mutated_job + workflow_text[fmt_end:]
    if set(variants) != set(WORKFLOW_CONTRACT_MUTATION_KINDS):
        raise DifferentialFailure("workflow contract mutation inventory drifted")
    return variants


candidate_workflows = candidate_workflow_sources()
checker_path = ROOT / DEPENDENCY_CHECKER
if not checker_path.is_file() or not os.access(checker_path, os.X_OK):
    raise SystemExit("witness dependency checker is missing or non-executable")

if mode == "normal":
    result = evaluate(scripts, candidate_workflows)
    render_normal(result)
    phase_error = None
    try:
        validate_candidate_contract(result, exact_unwired=False)
    except DifferentialFailure as error:
        phase_error = str(error)
        print(f"::error::{phase_error}", file=sys.stderr)
    else:
        print(f"phase285_transport_wiring required={len(REQUIRED_PHASE285)} observed={len(REQUIRED_PHASE285)} valid=1")
    normal_status = normal_mode_exit_code(result, phase_error)
    if normal_status == 0:
        print(
            "phase285_normal_wiring "
            f"parked={','.join(sorted(EXPECTED_UNWIRED))} "
            "unexpected_unwired=0 passed=1"
        )
    sys.exit(normal_status)

if mode == "self-test":
    before = subject_fingerprint()
    try:
        scratch_hostile_controls()
        actual = evaluate(scripts, candidate_workflows)
        validate_candidate_contract(actual, exact_unwired=True)
    except DifferentialFailure as error:
        raise SystemExit(f"Phase 285 wiring self-test refused: {error}") from None
    print(f"phase285_transport_wiring required={len(REQUIRED_PHASE285)} observed={len(REQUIRED_PHASE285)} valid=1")
    exact_normal_status = normal_mode_exit_code(actual, None)
    second_unwired = evaluate(
        [*scripts, "tools/check-phase285-added-unwired-mutant.sh"],
        candidate_workflows,
    )
    second_normal_status = normal_mode_exit_code(second_unwired, None)
    if exact_normal_status != 0 or second_normal_status == 0:
        raise SystemExit(
            "normal-mode parked singleton controls differ: "
            f"exact={exact_normal_status} second={second_normal_status}"
        )
    print(
        "phase285_normal_mode_controls "
        f"parked={len(EXPECTED_UNWIRED)} exact_singleton_exit={exact_normal_status} "
        f"second_unwired_exit={second_normal_status} passed=1"
    )
    ci_path = ".github/workflows/ci.yml"
    original_ci = candidate_workflows[ci_path]
    transport_mutations = 0
    contract_mutations = 0
    checker_mutations = 0
    with confined_scratch("phase285-wiring") as scratch:
        scratch_workflow = scratch / "ci.yml"
        for command in REQUIRED_PHASE285:
            try:
                variants = command_mutation_variants(original_ci, command)
            except DifferentialFailure as error:
                raise SystemExit(str(error)) from None
            for mutation_name, candidate_text in variants.items():
                scratch_workflow.write_text(candidate_text)
                mutated = dict(candidate_workflows)
                mutated[ci_path] = scratch_workflow.read_text()
                try:
                    validate_candidate_contract(
                        evaluate(scripts, mutated), exact_unwired=True
                    )
                except DifferentialFailure as error:
                    expected_reason = (
                        "Phase 285 workflow policy contract mismatch"
                        if mutation_name == "workflow-default-shell-noop"
                        else "Phase 285 fmt job contract mismatch"
                        if command == "cargo fmt --all -- --check"
                        else "Phase 285 workspace job contract mismatch"
                        if command == "cargo test --workspace --locked --offline"
                        else "Phase 285 job execution contract mismatch"
                    )
                    if str(error) != expected_reason:
                        raise SystemExit(
                            f"workflow mutation failed for wrong reason: "
                            f"{mutation_name}:{error}"
                        ) from None
                    transport_mutations += 1
                    print(
                        "phase285_wiring_red "
                        f"mutation={mutation_name}:{command.rsplit(' ', 1)[-1]} "
                        "accepted=0"
                    )
                else:
                    raise SystemExit(
                        f"workflow mutation passed: {mutation_name}:{command}"
                    )

        try:
            contract_variants = workflow_contract_mutation_variants(original_ci)
        except DifferentialFailure as error:
            raise SystemExit(str(error)) from None
        for mutation_name, candidate_text in contract_variants.items():
            mutated = dict(candidate_workflows)
            mutated[ci_path] = candidate_text
            expected_reason = (
                "Phase 285 workflow policy contract mismatch"
                if mutation_name in {
                    "trigger-path-restriction",
                    "permission-omission",
                    "permission-escalation",
                    "top-bash-env-addition",
                    "top-pythonpath-addition",
                }
                else "Phase 285 fmt job contract mismatch"
                if mutation_name.startswith("fmt-")
                else "Phase 285 workspace job contract mismatch"
                if mutation_name.startswith("workspace-")
                else "Phase 285 job execution contract mismatch"
            )
            try:
                validate_candidate_contract(evaluate(scripts, mutated), exact_unwired=True)
            except DifferentialFailure as error:
                if str(error) != expected_reason:
                    raise SystemExit(
                        f"workflow contract mutation failed for wrong reason: "
                        f"{mutation_name}:{error}"
                    ) from None
                contract_mutations += 1
                print(
                    "phase285_workflow_contract_red "
                    f"mutation={mutation_name} accepted=0"
                )
            else:
                raise SystemExit(
                    f"workflow contract mutation passed: {mutation_name}"
                )

        adjacent_anchor = "    name: mapping-contract (${{ github.sha }})\n"
        if original_ci.count(adjacent_anchor) != 1:
            raise SystemExit("adjacent job control anchor differs")
        adjacent = dict(candidate_workflows)
        adjacent[ci_path] = original_ci.replace(
            adjacent_anchor,
            "    name: mapping-contract-adjacent-control (${{ github.sha }})\n",
            1,
        )
        try:
            validate_candidate_contract(evaluate(scripts, adjacent), exact_unwired=True)
        except DifferentialFailure as error:
            raise SystemExit(
                f"adjacent job change altered Phase 285 contract: {error}"
            ) from None
        print("phase285_workflow_contract_adjacent_control isolated=1 passed=1")

        for checker in REQUIRED_PHASE285_CHECKERS:
            if checker not in original_ci:
                raise SystemExit(f"cannot build checker omission control: {checker}")
            scratch_workflow.write_text(original_ci.replace(checker, f"{checker}-foreign"))
            mutated = dict(candidate_workflows)
            mutated[ci_path] = scratch_workflow.read_text()
            try:
                validate_candidate_contract(evaluate(scripts, mutated), exact_unwired=True)
            except DifferentialFailure:
                checker_mutations += 1
            else:
                raise SystemExit(f"checker omission mutation passed: {checker}")
    after = subject_fingerprint()
    if after != before:
        raise SystemExit("Phase 285 wiring self-test wrote to its subject tree")
    expected_transport_mutations = len(COMMAND_MUTATION_KINDS) * len(REQUIRED_PHASE285)
    if (
        transport_mutations != expected_transport_mutations
        or contract_mutations != len(WORKFLOW_CONTRACT_MUTATION_KINDS)
        or checker_mutations != len(REQUIRED_PHASE285_CHECKERS)
    ):
        raise SystemExit(
            "Phase 285 wiring mutation count drift: "
            f"transport={transport_mutations} contract={contract_mutations} "
            f"checker={checker_mutations}"
        )
    print(
        f"phase285_transport_wiring_self_test entries={len(REQUIRED_PHASE285)} mutations={transport_mutations} passed=1"
    )
    print(f"phase285_wiring_self_test required={len(REQUIRED_PHASE285_CHECKERS)} observed={len(REQUIRED_PHASE285_CHECKERS)} omitted_lane_mutations={checker_mutations}")
    raise SystemExit(0)

if mode != "differential":
    raise SystemExit(f"unknown global wiring mode: {mode}")

before = subject_fingerprint()
try:
    base_snapshot = load_base(requested_base)
except DifferentialFailure as error:
    raise SystemExit(f"Phase 285 differential refused: {error}") from None
try:
    base_result, candidate_result = validate_pair(
        base_snapshot, scripts, candidate_workflows
    )
except DifferentialFailure as error:
    raise SystemExit(f"Phase 285 differential refused: {error}") from None
print(f"phase285_transport_wiring required={len(REQUIRED_PHASE285)} observed={len(REQUIRED_PHASE285)} valid=1")

mutations = 0


def require_rejection(label, operation, expected_reason=None):
    global mutations
    try:
        operation()
    except DifferentialFailure as error:
        if expected_reason is not None and str(error) != expected_reason:
            raise SystemExit(
                f"Phase 285 differential mutation failed for wrong reason: "
                f"{label}:{error}"
            ) from None
        mutations += 1
        print(f"phase285_differential_red mutation={label} accepted=0")
        return
    raise SystemExit(f"Phase 285 differential mutation passed: {label}")


require_rejection(
    "added-unwired-checker",
    lambda: validate_pair(
        base_snapshot,
        [*scripts, "tools/check-phase285-added-unwired-mutant.sh"],
        candidate_workflows,
    ),
)
require_rejection(
    "removed-baseline-singleton",
    lambda: validate_pair(
        base_snapshot,
        [script for script in scripts if script not in EXPECTED_UNWIRED],
        candidate_workflows,
    ),
)
require_rejection(
    "renamed-baseline-singleton",
    lambda: validate_pair(
        base_snapshot,
        [
            "tools/check-collective-hypothesis-graph-renamed.sh"
            if script in EXPECTED_UNWIRED else script
            for script in scripts
        ],
        candidate_workflows,
    ),
)

ci_path = ".github/workflows/ci.yml"
original_ci = candidate_workflows[ci_path]
for command in REQUIRED_PHASE285:
    try:
        variants = command_mutation_variants(original_ci, command)
    except DifferentialFailure as error:
        raise SystemExit(str(error)) from None
    for mutation_name, workflow_text in variants.items():
        mutated = dict(candidate_workflows)
        mutated[ci_path] = workflow_text
        require_rejection(
            f"{mutation_name}-invocation:{command.rsplit(' ', 1)[-1]}",
            lambda candidate=mutated: validate_pair(base_snapshot, scripts, candidate),
            (
                "Phase 285 workflow policy contract mismatch"
                if mutation_name == "workflow-default-shell-noop"
                else "Phase 285 fmt job contract mismatch"
                if command == "cargo fmt --all -- --check"
                else "Phase 285 workspace job contract mismatch"
                if command == "cargo test --workspace --locked --offline"
                else "Phase 285 job execution contract mismatch"
            ),
        )

try:
    contract_variants = workflow_contract_mutation_variants(original_ci)
except DifferentialFailure as error:
    raise SystemExit(str(error)) from None
for mutation_name, workflow_text in contract_variants.items():
    mutated = dict(candidate_workflows)
    mutated[ci_path] = workflow_text
    require_rejection(
        f"workflow-contract:{mutation_name}",
        lambda candidate=mutated: validate_pair(base_snapshot, scripts, candidate),
        (
            "Phase 285 workflow policy contract mismatch"
            if mutation_name in {
                "trigger-path-restriction",
                "permission-omission",
                "permission-escalation",
                "top-bash-env-addition",
                "top-pythonpath-addition",
            }
            else "Phase 285 fmt job contract mismatch"
            if mutation_name.startswith("fmt-")
            else "Phase 285 workspace job contract mismatch"
            if mutation_name.startswith("workspace-")
            else "Phase 285 job execution contract mismatch"
        ),
    )

adjacent_anchor = "    name: mapping-contract (${{ github.sha }})\n"
if original_ci.count(adjacent_anchor) != 1:
    raise SystemExit("differential adjacent job control anchor differs")
adjacent = dict(candidate_workflows)
adjacent[ci_path] = original_ci.replace(
    adjacent_anchor,
    "    name: mapping-contract-adjacent-control (${{ github.sha }})\n",
    1,
)
try:
    validate_pair(base_snapshot, scripts, adjacent)
except DifferentialFailure as error:
    raise SystemExit(
        f"differential adjacent job change altered Phase 285 contract: {error}"
    ) from None
print("phase285_differential_adjacent_job_control isolated=1 passed=1")

require_rejection(
    "altered-base-commit",
    lambda: load_base(
        git_bytes("rev-parse", "--verify", f"{EXPECTED_BASE}^{{commit}}^")
        .decode()
        .strip()
    ),
)

after = subject_fingerprint()
if after != before:
    raise SystemExit("Phase 285 differential wrote to its subject tree")
expected_differential_mutations = (
    4
    + len(COMMAND_MUTATION_KINDS) * len(REQUIRED_PHASE285)
    + len(WORKFLOW_CONTRACT_MUTATION_KINDS)
)
if mutations != expected_differential_mutations:
    raise SystemExit(f"Phase 285 differential mutation count drifted: {mutations}")
print(
    "phase285_global_wiring_differential "
    f"base={EXPECTED_BASE} base_unwired={len(base_result['unwired'])} "
    f"candidate_unwired={len(candidate_result['unwired'])} required={len(REQUIRED_PHASE285)} "
    f"checker_wired={dependency_invocation_step_count(candidate_result)} "
    f"mutations={mutations} subject_writes=0 passed=1"
)
PY

if [ "$PHASE285_GLOBAL_MODE" = self-test ]; then
  phase285_self_test
fi
