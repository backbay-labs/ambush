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

echo "checking ${#scripts[@]} gate script(s) against ${#workflows[@]} workflow(s)"

python3 - "${#scripts[@]}" "${scripts[@]}" "${workflows[@]}" <<'PY'
import sys

script_count = int(sys.argv[1])
scripts = sys.argv[2 : 2 + script_count]
workflows = sys.argv[2 + script_count :]

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


def parse_workflow(path):
    """Structural scan of the block-mapping subset GitHub workflows use.

    Returns (has_trigger, [(job_name, job_if, [step_dict, ...]), ...]).
    """
    with open(path, "r", encoding="utf-8") as handle:
        lines = handle.read().split("\n")

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


parsed_workflows = []
total_run_steps = 0
for path in workflows:
    has_trigger, jobs = parse_workflow(path)
    if not jobs:
        print(
            f"::error::{path} parsed to zero jobs; refusing to pass silently",
            file=sys.stderr,
        )
        sys.exit(1)
    if not has_trigger:
        print(f"note: {path} declares no `on:` trigger; its jobs do not count as wired")
    total_run_steps += sum(1 for _, _, steps in jobs for step in steps if step["run"])
    parsed_workflows.append((path, has_trigger, jobs))

if total_run_steps == 0:
    print(
        "::error::parsed zero `run:` steps across all workflows; the scanner is "
        "broken and would report every gate as unwired",
        file=sys.stderr,
    )
    sys.exit(1)

print(f"parsed {total_run_steps} run-steps across {len(parsed_workflows)} workflow(s)")

status = 0
for script in scripts:
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

    if wired_at:
        print(f"wired: {script}")
        for where in wired_at:
            print(f"    {where}")
        continue

    status = 1
    print(f"::error::{script} is invoked by no workflow step", file=sys.stderr)
    for where in rejected:
        print(f"::error::  rejected: {where}", file=sys.stderr)
    if not rejected:
        print(
            f"::error::  no `run:` command in .github/workflows/ mentions {script}",
            file=sys.stderr,
        )

sys.exit(status)
PY

echo "every gate script is wired into a workflow"
