#!/usr/bin/env python3
"""Fail-closed structural verifier for the Phase 286 Nyquist matrix."""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass
from pathlib import Path


PHASE_DIR = Path(".planning/phases/286-collective-hypothesis-graph")
VALIDATION = PHASE_DIR / "286-VALIDATION.md"
EVIDENCE = PHASE_DIR / "286-VALIDATION-EVIDENCE.md"
ROW_RE = re.compile(r"^\|\s*(286-[0-9A-Z]+-[0-9]{2})\s*\|(.+)\|$")
TASK_RE = re.compile(r'<task\s+type="[^"]+"')
PLAN_RE = re.compile(r"286-([0-9A-Z]+)-PLAN\.md$")
REQUIRED_HEADERS = (
    "Task ID",
    "Plan",
    "Wave",
    "Requirement",
    "Test Type",
    "Automated Command",
    "Artifact Evidence",
    "Status",
)


class MatrixError(ValueError):
    pass


@dataclass(frozen=True)
class TaskContract:
    plan_id: str
    wave: int
    requirements: frozenset[str]
    files: tuple[Path, ...]
    automated_command: str


@dataclass(frozen=True)
class EvidenceEntry:
    command: str
    passed_count: int


def expand_requirements(value: str) -> frozenset[str]:
    expanded: set[str] = set()
    for token in (part.strip() for part in value.split(",")):
        match = re.fullmatch(r"COG-(\d{2})\.\.COG-(\d{2})", token)
        if match:
            start, end = (int(part) for part in match.groups())
            if start > end:
                raise MatrixError(f"reversed requirement range: {token}")
            expanded.update(f"COG-{number:02d}" for number in range(start, end + 1))
        elif re.fullmatch(r"COG-\d{2}", token):
            expanded.add(token)
        else:
            raise MatrixError(f"invalid requirement expression: {token}")
    if not expanded:
        raise MatrixError("requirement set must not be empty")
    return frozenset(expanded)


def task_inventory(root: Path) -> dict[str, TaskContract]:
    phase_dir = root / PHASE_DIR
    inventory: dict[str, TaskContract] = {}
    for plan_path in sorted(phase_dir.glob("286-*-PLAN.md")):
        match = PLAN_RE.fullmatch(plan_path.name)
        if match is None:
            continue
        plan_id = match.group(1)
        plan_text = plan_path.read_text(encoding="utf-8")
        wave_match = re.search(r"^wave:\s*(\d+)\s*$", plan_text, re.MULTILINE)
        requirements_match = re.search(r"^requirements:\s*\[([^]]+)\]\s*$", plan_text, re.MULTILINE)
        if wave_match is None or requirements_match is None:
            raise MatrixError(f"plan lacks wave or requirements metadata: {plan_path}")
        wave = int(wave_match.group(1))
        requirements = expand_requirements(requirements_match.group(1))
        task_blocks = re.findall(r"<task\s+[^>]+>(.*?)</task>", plan_text, re.DOTALL)
        if not task_blocks:
            raise MatrixError(f"plan has no tasks: {plan_path}")
        for ordinal, block in enumerate(task_blocks, start=1):
            files_match = re.search(r"<files>(.*?)</files>", block, re.DOTALL)
            verify_match = re.search(
                r"<verify>\s*<automated>(.*?)</automated>\s*</verify>",
                block,
                re.DOTALL,
            )
            if files_match is None or verify_match is None:
                raise MatrixError(f"plan task lacks files or automated verify: {plan_path}#{ordinal}")
            files = tuple(
                root / Path(value.strip())
                for value in files_match.group(1).split(",")
                if value.strip()
            )
            inventory[f"286-{plan_id}-{ordinal:02d}"] = TaskContract(
                plan_id=plan_id,
                wave=wave,
                requirements=requirements,
                files=files,
                automated_command=" ".join(verify_match.group(1).split()),
            )
    if not inventory:
        raise MatrixError("no Phase 286 execution plans found")
    return inventory


def parse_matrix(text: str) -> dict[str, tuple[str, ...]]:
    header = "| " + " | ".join(REQUIRED_HEADERS) + " |"
    if text.count(header) != 1:
        raise MatrixError("validation matrix must contain exactly one canonical header")

    rows: dict[str, tuple[str, ...]] = {}
    for line in text.splitlines():
        match = ROW_RE.match(line)
        if match is None:
            continue
        task_id = match.group(1)
        cells = tuple(cell.strip() for cell in match.group(2).split("|"))
        if len(cells) != len(REQUIRED_HEADERS) - 1:
            raise MatrixError(f"{task_id}: expected {len(REQUIRED_HEADERS)} columns")
        if task_id in rows:
            raise MatrixError(f"duplicate validation row: {task_id}")
        if any(not cell for cell in cells):
            raise MatrixError(f"{task_id}: empty validation cell")
        rows[task_id] = cells
    return rows


def parse_evidence_ledger(text: str) -> dict[str, EvidenceEntry]:
    entries: dict[str, EvidenceEntry] = {}
    matches = list(
        re.finditer(
            r"^## (286-[0-9A-Z]+-[0-9]{2})\s*$\n(?P<body>.*?)(?=^## 286-|\Z)",
            text,
            re.MULTILINE | re.DOTALL,
        )
    )
    for match in matches:
        heading = match.group(1)
        if heading in entries:
            raise MatrixError(f"duplicate evidence entry: {heading}")
        body = match.group("body")
        fields: dict[str, str] = {}
        for line in (line.strip() for line in body.splitlines() if line.strip()):
            if ": " not in line:
                raise MatrixError(f"{heading}: malformed evidence field")
            key, value = line.split(": ", 1)
            if key in fields:
                raise MatrixError(f"{heading}: duplicate evidence field: {key}")
            fields[key] = value.strip()
        expected_fields = {
            "task_id",
            "command",
            "result_status",
            "passed_count",
            "failed_count",
        }
        if set(fields) != expected_fields:
            raise MatrixError(f"{heading}: evidence fields must be exactly {sorted(expected_fields)}")
        if fields["task_id"] != heading:
            raise MatrixError(f"{heading}: evidence task_id must match heading")
        if not fields["command"]:
            raise MatrixError(f"{heading}: evidence command must not be empty")
        if fields["result_status"] != "pass":
            raise MatrixError(f"{heading}: result_status must be exactly pass")
        if not re.fullmatch(r"[0-9]+", fields["passed_count"]):
            raise MatrixError(f"{heading}: passed_count must be an integer")
        if not re.fullmatch(r"[0-9]+", fields["failed_count"]):
            raise MatrixError(f"{heading}: failed_count must be an integer")
        passed_count = int(fields["passed_count"])
        failed_count = int(fields["failed_count"])
        if passed_count < 1 or failed_count != 0:
            raise MatrixError(f"{heading}: evidence must have passed_count >= 1 and failed_count == 0")
        entries[heading] = EvidenceEntry(
            command=" ".join(fields["command"].split()),
            passed_count=passed_count,
        )
    if not entries:
        raise MatrixError("evidence ledger has no entries")
    return entries


def evidence_anchors(command: str) -> frozenset[str]:
    words = command.split()
    anchors: set[str] = set()
    for index, word in enumerate(words):
        if word == "--test" and index + 1 < len(words):
            anchors.add(words[index + 1])
        elif word.startswith("tools/"):
            anchors.add(word)
        elif "::" in word and not word.startswith("-"):
            anchors.add(word)
        elif (
            word == "--exact"
            and index + 1 < len(words)
            and not words[index + 1].startswith("-")
            and words[index + 1] not in {"&&", "||", ";"}
        ):
            anchors.add(words[index + 1])
    return frozenset(anchors)


def verify_text(root: Path, text: str, *, strict: bool) -> None:
    inventory = task_inventory(root)
    rows = parse_matrix(text)
    expected = set(inventory)
    actual = set(rows)
    missing = sorted(expected - actual)
    extra = sorted(actual - expected)
    if missing or extra:
        raise MatrixError(f"matrix/task mismatch: missing={missing}, extra={extra}")

    required_terms = (
        "preflight_complete",
        "wave_0_complete",
        "It is not numeric execution-wave completion",
        "execution waves 3 through 13",
        "286-06B-01",
        "286-06B-02",
    )
    for term in required_terms:
        if term not in text:
            raise MatrixError(f"missing validation contract term: {term}")

    if strict:
        if not re.search(r"^preflight_complete:\s*true\s*$", text, re.MULTILINE):
            raise MatrixError("preflight_complete must be exactly true")
        if not re.search(r"^wave_0_complete:\s*true\s*$", text, re.MULTILINE):
            raise MatrixError("wave_0_complete must be exactly true")
        evidence_path = root / EVIDENCE
        evidence_entries = (
            parse_evidence_ledger(evidence_path.read_text(encoding="utf-8"))
            if evidence_path.is_file()
            else {}
        )
        green_task_ids: set[str] = set()
        forbidden = ("--watch", "cargo watch", "|| true")
        for task_id, cells in rows.items():
            contract = inventory[task_id]
            row_plan, row_wave, row_requirements = cells[0], cells[1], cells[2]
            test_type = cells[3].lower()
            command = cells[4].strip("`")
            artifact_state = cells[5]
            evidence_state = cells[6]
            if row_plan != contract.plan_id:
                raise MatrixError(f"{task_id}: plan metadata mismatch")
            if row_wave != str(contract.wave):
                raise MatrixError(f"{task_id}: wave metadata mismatch")
            if not expand_requirements(row_requirements).issubset(contract.requirements):
                raise MatrixError(f"{task_id}: requirement metadata exceeds plan ownership")
            if any(token in command for token in forbidden):
                raise MatrixError(f"{task_id}: bypassable or watch-mode command")
            if not any(token in command for token in ("cargo test", "bash ", "python3 ")):
                raise MatrixError(f"{task_id}: command is not an executable checker")
            if len(test_type) < 5:
                raise MatrixError(f"{task_id}: test type lacks a concrete control")
            if not any(token in artifact_state for token in ("✅", "⬜", "❌", "⚠️")):
                raise MatrixError(f"{task_id}: artifact state is not explicit")
            if not any(token in evidence_state for token in ("✅", "⬜", "❌", "⚠️")):
                raise MatrixError(f"{task_id}: evidence state is not explicit")
            normalized_command = " ".join(command.split())
            if normalized_command != contract.automated_command:
                raise MatrixError(f"{task_id}: command differs from its complete task verify")
            artifact_green = artifact_state.startswith("✅")
            evidence_green = evidence_state.startswith("✅")
            if artifact_green != evidence_green:
                raise MatrixError(f"{task_id}: artifact/evidence green state disagrees")
            if artifact_green:
                green_task_ids.add(task_id)
                missing_files = [str(path) for path in contract.files if not path.exists()]
                if missing_files:
                    raise MatrixError(f"{task_id}: green row has missing artifacts: {missing_files}")
                summary = root / PHASE_DIR / f"286-{contract.plan_id}-SUMMARY.md"
                if not summary.is_file():
                    raise MatrixError(f"{task_id}: green row lacks a verification summary")
                summary_text = summary.read_text(encoding="utf-8")
                if "## Verification" not in summary_text:
                    raise MatrixError(f"{task_id}: green row lacks a verification section")
                absent_anchors = sorted(
                    anchor for anchor in evidence_anchors(command) if anchor not in summary_text
                )
                if absent_anchors:
                    raise MatrixError(
                        f"{task_id}: green row lacks command evidence anchors: {absent_anchors}"
                    )
                entry = evidence_entries.get(task_id)
                if entry is None or entry.command != normalized_command:
                    raise MatrixError(f"{task_id}: green row lacks exact command evidence")
        if set(evidence_entries) != green_task_ids:
            raise MatrixError(
                "evidence ledger entries must exactly equal green rows: "
                f"ledger={sorted(evidence_entries)}, green={sorted(green_task_ids)}"
            )


def self_test(root: Path, text: str) -> None:
    verify_text(root, text, strict=True)
    mutations = {
        "missing-row": re.sub(r"^\| 286-01D-02 .*$\n?", "", text, count=1, flags=re.MULTILINE),
        "duplicate-row": text + next(
            line + "\n" for line in text.splitlines() if line.startswith("| 286-06B-02 ")
        ),
        "extra-row": text + next(
            line.replace("286-00-01", "286-00-99", 1) + "\n"
            for line in text.splitlines()
            if line.startswith("| 286-00-01 ")
        ),
        "fake-command": text.replace(
            "cargo test -p swarm-runtime --lib --locked --offline canary::tests::canary_support_config_preserves_disabled_graph_and_legacy_runtime_bytes -- --exact --nocapture",
            "python3 -c 'pass'",
            1,
        ),
        "truncated-command": text.replace(
            "cargo test -p swarm-runtime --test collective_hypothesis_oracle benchmark_manifest_is_strict --locked --offline -- --exact",
            "cargo test",
            1,
        ),
        "omitted-command-segment": text.replace(
            " && cargo test -p swarm-runtime --lib --locked --offline promotion::tests::promotion_support_config_preserves_disabled_graph_and_legacy_runtime_bytes -- --exact --nocapture && cargo test -p swarm-runtime --lib --locked --offline service::tests::service_support_config_preserves_disabled_graph_and_legacy_runtime_bytes -- --exact --nocapture",
            "",
            1,
        ),
        "wrong-wave": text.replace("| 286-01B-01 | 01B | 4 |", "| 286-01B-01 | 01B | 99 |", 1),
        "wrong-plan": text.replace("| 286-01B-01 | 01B | 4 |", "| 286-01B-01 | 01C | 4 |", 1),
        "wrong-requirement": text.replace("| 286-07B-01 | 07B | 13 | COG-08 |", "| 286-07B-01 | 07B | 13 | COG-01 |", 1),
        "reversed-requirement": text.replace(
            "| 286-07-03 | 07 | 12 | COG-01..COG-08 |",
            "| 286-07-03 | 07 | 12 | COG-99..COG-01 |",
            1,
        ),
        "fake-green-status": re.sub(
            r"^(\| 286-01C-01 .*?)\| ⬜ pending \| ⬜ pending \|$",
            r"\1| ✅ | ✅ green |",
            text,
            count=1,
            flags=re.MULTILINE,
        ),
        "fake-broad-green-status": re.sub(
            r"^(\| 286-01-01 .*?)\| ⬜ pending \| ⬜ pending \|$",
            r"\1| ✅ | ✅ green |",
            text,
            count=1,
            flags=re.MULTILINE,
        ),
        "ambiguous-wave": text.replace(
            "It is not numeric execution-wave completion",
            "It is numeric execution-wave completion",
            1,
        ),
        "watch-command": text.replace(
            "cargo test -p swarm-runtime --lib --locked --offline canary::tests::canary_support_config_preserves_disabled_graph_and_legacy_runtime_bytes",
            "cargo watch -x test",
            1,
        ),
        "empty-cell": text.replace(
            "| sealed strict adjudicated oracle + pinned digests |",
            "|  |",
            1,
        ),
    }
    for name, mutation in mutations.items():
        try:
            verify_text(root, mutation, strict=True)
        except MatrixError:
            continue
        raise MatrixError(f"self-test mutation was accepted: {name}")

    evidence_text = (root / EVIDENCE).read_text(encoding="utf-8")
    evidence_mutations = {
        "missing-result": re.sub(
            r"^result_status: pass\s*$",
            "",
            evidence_text,
            count=1,
            flags=re.MULTILINE,
        ),
        "mismatched-task": evidence_text.replace(
            "task_id: 286-00-01",
            "task_id: 286-00-02",
            1,
        ),
        "duplicate-entry": evidence_text
        + "\n## 286-00-01\n\ntask_id: 286-00-01\ncommand: cargo test\nresult_status: pass\npassed_count: 1\nfailed_count: 0\n",
        "zero-pass-count": evidence_text.replace("passed_count: 1", "passed_count: 0", 1),
        "nonzero-failure-count": evidence_text.replace("failed_count: 0", "failed_count: 1", 1),
        "dishonest-result-prose": evidence_text.replace(
            "result_status: pass\npassed_count: 1\nfailed_count: 0",
            "result: 1 passed; failed tests: 1",
            1,
        ),
    }
    for name, mutation in evidence_mutations.items():
        try:
            parse_evidence_ledger(mutation)
        except MatrixError:
            continue
        raise MatrixError(f"evidence self-test mutation was accepted: {name}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--cwd", default=".")
    parser.add_argument("--strict", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    root = Path(args.cwd).resolve()
    validation_path = root / VALIDATION
    try:
        text = validation_path.read_text(encoding="utf-8")
        verify_text(root, text, strict=args.strict)
        if args.self_test:
            self_test(root, text)
    except (OSError, MatrixError) as error:
        print(f"phase286-validation: FAIL: {error}", file=sys.stderr)
        return 1
    print(f"phase286-validation: PASS ({len(parse_matrix(text))} task rows)")
    if args.self_test:
        print("phase286-validation: PASS (21 fail-closed mutations rejected)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
