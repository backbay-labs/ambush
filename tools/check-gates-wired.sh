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

python3 - "$PHASE285_GLOBAL_MODE" "$PHASE285_BASE_COMMIT" \
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


def normalize_condition(value):
    text = value.strip()
    if text.startswith("${{") and text.endswith("}}"):
        text = text[3:-2]
    return " ".join(text.split())


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


def parse_workflow(path, text):
    """Structural scan of the block-mapping subset GitHub workflows use.

    Returns (has_trigger, [(job_name, job_if, [step_dict, ...]), ...]).
    """
    lines = text.split("\n")

    has_trigger = False
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
                        current = {"name": None, "if": None, "run": None}
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
                    if step_key not in ("name", "if", "run"):
                        index += 1
                        continue
                    if step_value in ("|", "|-", "|+", ">", ">-", ">+", ""):
                        body, index = collect_block(lines, index + 1, line_indent)
                        current[step_key] = body
                        continue
                    current[step_key] = step_value
                    index += 1

            jobs.append((job_name, job_if, steps))

    return has_trigger, jobs


ROOT = pathlib.Path.cwd().resolve()
EXPECTED_BASE = "ff762236a216f44d26da90d7b3fe7eeecc3d178d"
EXPECTED_UNWIRED = {"tools/check-collective-hypothesis-graph.sh"}
DEPENDENCY_CHECKER = "tools/check-witness-dependency-closure.sh"
REQUIRED_PHASE285 = [
    "bash tools/check-phase285-witness-conformance.sh response-failure-wire",
    "bash tools/check-phase285-witness-conformance.sh candidate-verifier",
    "bash tools/check-phase285-witness-conformance.sh protocol-checkpoint",
    "bash tools/check-phase285-witness-conformance.sh atomic-store-contract",
    "bash tools/check-phase285-witness-conformance.sh in-memory-differential",
    "bash tools/check-phase285-witness-conformance.sh typed-proxy",
    "bash tools/check-phase285-witness-conformance.sh transport-layering",
    "bash tools/check-witness-dependency-closure.sh --library-only",
]
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
        has_trigger, jobs = parse_workflow(path, workflow_sources[path])
        if not jobs:
            errors.append(f"{path} parsed to zero jobs; refusing to pass silently")
            continue
        if not has_trigger:
            errors.append(
                f"note: {path} declares no `on:` trigger; its jobs do not count as wired"
            )
        total_run_steps += sum(
            1 for _, _, steps in jobs for step in steps if step["run"]
        )
        parsed_workflows.append((path, has_trigger, jobs))
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
        for path, has_trigger, jobs in parsed_workflows:
            for job_name, job_if, steps in jobs:
                for step in steps:
                    run = step["run"]
                    if not run or script not in run:
                        continue
                    where = f"{path}:{job_name}:{step['name'] or '<unnamed step>'}"
                    if not has_trigger:
                        rejected.append(f"{where} (workflow has no `on:` trigger)")
                        continue
                    if job_if is not None and (
                        normalize_condition(job_if) not in PERMISSIVE_CONDITIONS
                    ):
                        rejected.append(f"{where} (job guarded by `if: {job_if}`)")
                        continue
                    if step["if"] is not None and (
                        normalize_condition(step["if"]) not in PERMISSIVE_CONDITIONS
                    ):
                        rejected.append(f"{where} (step guarded by `if: {step['if']}`)")
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
def confined_scratch(prefix, parent=None):
    requested_parent = pathlib.Path(
        parent if parent is not None else os.environ.get("TMPDIR", tempfile.gettempdir())
    ).resolve(strict=True)
    boundaries = git_boundaries()
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
        for boundary in boundaries
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
    for boundary in git_boundaries():
        had_tmpdir = "TMPDIR" in os.environ
        original_tmpdir = os.environ.get("TMPDIR")
        try:
            os.environ["TMPDIR"] = str(boundary)
            with confined_scratch("phase285-wiring-hostile"):
                pass
        except ScratchBoundaryFailure:
            rejected += 1
        else:
            raise DifferentialFailure(
                f"hostile TMPDIR boundary was accepted: {boundary}"
            )
        finally:
            if had_tmpdir:
                os.environ["TMPDIR"] = original_tmpdir
            else:
                os.environ.pop("TMPDIR", None)
    if rejected != 3:
        raise DifferentialFailure(f"hostile scratch control count drifted: {rejected}")
    print(f"phase285_scratch_self_test site=gates boundaries={rejected} passed=1")


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
    for _, has_trigger, jobs in result["parsed_workflows"]:
        if not has_trigger:
            continue
        for _, job_if, steps in jobs:
            if job_if is not None and normalize_condition(job_if) not in PERMISSIVE_CONDITIONS:
                continue
            for step in steps:
                if step["if"] is not None and (
                    normalize_condition(step["if"]) not in PERMISSIVE_CONDITIONS
                ):
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


def required_checker_counts(result):
    runs = valid_run_texts(result)
    counts = {}
    for checker in REQUIRED_PHASE285_CHECKERS:
        pattern = re.compile(
            rf"(?<![A-Za-z0-9_./-]){re.escape(checker)}(?![A-Za-z0-9_./-])"
        )
        counts[checker] = sum(len(pattern.findall(run)) for run in runs)
    return counts


def validate_candidate_contract(result, *, exact_unwired):
    errors = [error for error in result["errors"] if not error.startswith("note:")]
    if errors:
        raise DifferentialFailure(f"structural parser error: {errors}")
    if exact_unwired and result["unwired"] != EXPECTED_UNWIRED:
        raise DifferentialFailure(
            f"candidate unwired set mismatch: {sorted(result['unwired'])}"
        )
    command_counts = exact_command_counts(result)
    if any(count != 1 for count in command_counts.values()):
        raise DifferentialFailure(f"Phase 285 invocation mismatch: {command_counts}")
    checker_counts = required_checker_counts(result)
    if any(count == 0 for count in checker_counts.values()):
        raise DifferentialFailure(f"Phase 285 checker wiring mismatch: {checker_counts}")
    if DEPENDENCY_CHECKER not in result["wiring"]:
        raise DifferentialFailure("witness dependency checker absent from candidate inventory")
    if len(result["wiring"].get(DEPENDENCY_CHECKER, [])) != 1:
        raise DifferentialFailure("witness dependency checker is not wired exactly once")
    return command_counts, checker_counts


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
        print("phase285_transport_wiring required=8 observed=8 valid=1")
    normal_errors = [error for error in result["errors"] if not error.startswith("note:")]
    sys.exit(1 if normal_errors or result["unwired"] or phase_error else 0)

if mode == "self-test":
    before = subject_fingerprint()
    try:
        scratch_hostile_controls()
        actual = evaluate(scripts, candidate_workflows)
        validate_candidate_contract(actual, exact_unwired=True)
    except DifferentialFailure as error:
        raise SystemExit(f"Phase 285 wiring self-test refused: {error}") from None
    print("phase285_transport_wiring required=8 observed=8 valid=1")
    ci_path = ".github/workflows/ci.yml"
    original_ci = candidate_workflows[ci_path]
    transport_mutations = 0
    checker_mutations = 0
    with confined_scratch("phase285-wiring") as scratch:
        scratch_workflow = scratch / "ci.yml"
        for command in REQUIRED_PHASE285:
            if original_ci.count(command) != 1:
                raise SystemExit(f"cannot build exact workflow controls for {command}")
            if command.endswith("--library-only"):
                deleted = original_ci.replace(f"        run: {command}\n", "", 1)
                duplicated = original_ci.replace(
                    f"        run: {command}\n",
                    f"        run: |\n          {command}\n          {command}\n",
                    1,
                )
            else:
                deleted = original_ci.replace(f"          {command}\n", "", 1)
                duplicated = original_ci.replace(
                    f"          {command}\n",
                    f"          {command}\n          {command}\n",
                    1,
                )
            variants = {
                "deletion": deleted,
                "duplication": duplicated,
                "selector_mode": original_ci.replace(
                    command,
                    command.replace("--library-only", "--all-targets")
                    if "--library-only" in command else f"{command}-foreign",
                    1,
                ),
                "command": original_ci.replace(
                    command, command.replace("bash ", "sh ", 1), 1
                ),
            }
            for mutation_name, candidate_text in variants.items():
                scratch_workflow.write_text(candidate_text)
                mutated = dict(candidate_workflows)
                mutated[ci_path] = scratch_workflow.read_text()
                try:
                    validate_candidate_contract(
                        evaluate(scripts, mutated), exact_unwired=True
                    )
                except DifferentialFailure:
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
    if transport_mutations != 32 or checker_mutations != 6:
        raise SystemExit(
            "Phase 285 wiring mutation count drift: "
            f"transport={transport_mutations} checker={checker_mutations}"
        )
    print(
        "phase285_transport_wiring_self_test entries=8 mutations=32 passed=1"
    )
    print("phase285_wiring_self_test required=6 observed=6 omitted_lane_mutations=6")
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
print("phase285_transport_wiring required=8 observed=8 valid=1")

mutations = 0


def require_rejection(label, operation):
    global mutations
    try:
        operation()
    except DifferentialFailure:
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
    if original_ci.count(command) != 1:
        raise SystemExit(f"cannot build exact invocation controls for {command}")
    deleted = dict(candidate_workflows)
    deleted[ci_path] = original_ci.replace(command, "", 1)
    require_rejection(
        f"deleted-invocation:{command.rsplit(' ', 1)[-1]}",
        lambda candidate=deleted: validate_pair(base_snapshot, scripts, candidate),
    )
    replacement = (
        command.replace("--library-only", "--all-targets")
        if command.endswith("--library-only")
        else f"{command}-foreign"
    )
    substituted = dict(candidate_workflows)
    substituted[ci_path] = original_ci.replace(command, replacement, 1)
    require_rejection(
        f"substituted-invocation:{command.rsplit(' ', 1)[-1]}",
        lambda candidate=substituted: validate_pair(base_snapshot, scripts, candidate),
    )

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
if mutations != 20:
    raise SystemExit(f"Phase 285 differential mutation count drifted: {mutations}")
print(
    "phase285_global_wiring_differential "
    f"base={EXPECTED_BASE} base_unwired={len(base_result['unwired'])} "
    f"candidate_unwired={len(candidate_result['unwired'])} required=8 "
    f"checker_wired={len(candidate_result['wiring'][DEPENDENCY_CHECKER])} "
    f"mutations={mutations} subject_writes=0 passed=1"
)
PY

if [ "$PHASE285_GLOBAL_MODE" = self-test ]; then
  phase285_self_test
elif [ "$PHASE285_GLOBAL_MODE" = normal ]; then
  echo "every gate script is wired into a workflow"
fi
