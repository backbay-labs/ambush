#!/usr/bin/env bash
#
# Invariant-map gate (MAPPING-03, MAPPING-04, MAPPING-05; phase 285).
#
# WHY THIS EXISTS
#   `docs/assurance/MAPPING.md` claims that each fail-closed invariant is
#   enforced by a named `crate::module::function`. A markdown table cannot go
#   stale loudly: rename the function and the row still reads correctly, delete
#   the guard and the row still reads correctly. A table nobody checks is the
#   documentation form of the defect `.planning/STATE.md` catalogues twelve
#   times -- a claim reporting success over a region it never inspected.
#
# WHAT IS CHECKED
#   1. Every `// INVARIANT: <NAME>` marker in production code under
#      `crates/*/src` has a row in MAPPING.md. (MAPPING-04, first half.)
#   2. Every MAPPING.md row resolves to a real declaration: the crate exists,
#      the module file exists, the named type is declared in it, and a
#      `fn <name>` is declared in it. (MAPPING-04, second half.)
#   3. Every MAPPING.md row has its marker IN THE FILE IT RESOLVES TO. A marker
#      parked in an unrelated file does not satisfy a row.
#   4. Every row's assumption is declared in `docs/assurance/assumptions.toml`,
#      every assumption carries a non-empty owner and statement, and each
#      assumption's `invariants` list equals EXACTLY the set of rows naming it
#      -- as a set, in both directions. An assumption with no dependent rows is
#      allowed and must carry `no_dependent_invariants_reason`.
#   5. Coverage floors from the phase's success criteria: >= 12 rows, >= 4
#      distinct crates, >= 8 assumptions. Below any of these the map is not yet
#      the thing the phase asked for, and a green gate would say it was.
#
# WHAT IS NOT CHECKED, DELIBERATELY
#   - That the named function actually enforces what the row says. No static
#     check can establish that; `tools/check-negative-registry.sh` requires a
#     mutation test per row, and review reads it.
#   - Markers inside `#[cfg(test)]`. Production text is everything above the
#     first column-0 `#[cfg(test)]` in a file. That truncation is an
#     approximation and the self-test exercises it in both directions: a
#     function that exists ONLY under `#[cfg(test)]` must NOT satisfy a row.
#   - `.inc` files. `tools/check-no-include-files.sh` keeps new ones out and
#     the one allow-listed file carries no rows.
#
# SELF-TEST
#   Every invocation first builds synthetic repositories in a temp directory and
#   runs the SAME checker over them: one clean tree that must pass, and twelve
#   broken trees that must each be caught with the right diagnostic. If any case
#   misbehaves the script exits 1 WITHOUT looking at the real tree, because a
#   broken checker is a broken gate rather than a green one.
#
#   Case `unmapped_marker` is success criterion 3 of phase 285 in executable
#   form: a deliberately unmapped `// INVARIANT:` marker must fail the build.
#
set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

python3 - "$ROOT_DIR" <<'PY'
from __future__ import annotations

import pathlib
import re
import sys
import tempfile
import tomllib

REPO_ROOT = pathlib.Path(sys.argv[1])

MAPPING_REL = "docs/assurance/MAPPING.md"
ASSUMPTIONS_REL = "docs/assurance/assumptions.toml"

MARKER = re.compile(r"//\s*INVARIANT:\s*(?P<name>[A-Z0-9][A-Z0-9-]*)\s*$", re.M)
CFG_TEST_AT_COL0 = re.compile(r"^#\[cfg\(test\)\]", re.M)
# A table row: | `INV` | `path` | `ASSUME-X` | prose |
ROW = re.compile(
    r"^\|\s*`(?P<invariant>[A-Z0-9][A-Z0-9-]*)`\s*"
    r"\|\s*`(?P<function>[A-Za-z0-9_:]+)`\s*"
    r"\|\s*`(?P<assumption>[A-Z0-9][A-Z0-9-]*)`\s*"
    r"\|(?P<summary>[^|]*)\|\s*$",
    re.M,
)


class Report:
    def __init__(self, label: str) -> None:
        self.label = label
        self.violations: list[tuple[str, str]] = []

    def violation(self, code: str, message: str) -> None:
        self.violations.append((code, message))

    def codes(self) -> set[str]:
        return {code for code, _ in self.violations}


def production_text(path: pathlib.Path) -> str:
    """File text with the trailing column-0 `#[cfg(test)]` item onwards removed."""
    text = path.read_text(encoding="utf-8", errors="replace")
    match = CFG_TEST_AT_COL0.search(text)
    return text[: match.start()] if match else text


def parse_rows(root: pathlib.Path, report: Report):
    path = root / MAPPING_REL
    if not path.is_file():
        report.violation("mapping-missing", f"{MAPPING_REL} does not exist")
        return []
    rows = []
    for match in ROW.finditer(path.read_text(encoding="utf-8")):
        rows.append(
            {
                "invariant": match.group("invariant"),
                "function": match.group("function"),
                "assumption": match.group("assumption"),
                "summary": match.group("summary").strip(),
            }
        )
    return rows


def parse_assumptions(root: pathlib.Path, report: Report):
    path = root / ASSUMPTIONS_REL
    if not path.is_file():
        report.violation("assumptions-missing", f"{ASSUMPTIONS_REL} does not exist")
        return []
    try:
        document = tomllib.loads(path.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError as error:
        report.violation("assumptions-unparseable", f"{ASSUMPTIONS_REL}: {error}")
        return []
    return document.get("assumption", [])


def collect_markers(root: pathlib.Path):
    """Every `// INVARIANT: X` in production code, as (name, file) pairs."""
    found = []
    crates = root / "crates"
    if not crates.is_dir():
        return found
    for source in sorted(crates.glob("*/src/**/*.rs")):
        text = production_text(source)
        for match in MARKER.finditer(text):
            found.append((match.group("name"), source))
    return found


def resolve_function(root: pathlib.Path, path_str: str):
    """Resolve `crate::module::Type::function` to (file, type_name, fn_name).

    Returns (None, reason) when it cannot be resolved.
    """
    segments = path_str.split("::")
    if len(segments) < 2:
        return None, f"`{path_str}` is not a `crate::...::function` path"

    crate_dir = root / "crates" / segments[0].replace("_", "-") / "src"
    if not crate_dir.is_dir():
        return None, f"crate `{segments[0]}` has no `crates/*/src` directory"

    rest = segments[1:]
    current_dir = crate_dir
    module_file = None
    index = 0
    while index < len(rest):
        segment = rest[index]
        if not (segment[:1].islower() or segment.startswith("_")):
            break
        directory = current_dir / segment
        file = current_dir / f"{segment}.rs"
        if directory.is_dir():
            current_dir = directory
            index += 1
            continue
        if file.is_file():
            module_file = file
            index += 1
        break

    if module_file is None:
        module_file = (
            current_dir / "mod.rs" if current_dir != crate_dir else crate_dir / "lib.rs"
        )
    if not module_file.is_file():
        return None, f"`{path_str}` resolves to `{module_file}`, which does not exist"

    remaining = rest[index:]
    if len(remaining) == 1:
        type_name, fn_name = None, remaining[0]
    elif len(remaining) == 2 and remaining[0][:1].isupper():
        type_name, fn_name = remaining
    else:
        return None, f"`{path_str}` does not end in `function` or `Type::function`"
    return (module_file, type_name, fn_name), None


def check_row_resolves(root: pathlib.Path, row, report: Report):
    resolved, reason = resolve_function(root, row["function"])
    if resolved is None:
        report.violation(
            "row-path-unresolvable",
            f"row `{row['invariant']}` names `{row['function']}`: {reason}",
        )
        return None
    module_file, type_name, fn_name = resolved
    text = production_text(module_file)
    if not re.search(r"\bfn\s+" + re.escape(fn_name) + r"\s*[(<]", text):
        report.violation(
            "row-function-absent",
            f"row `{row['invariant']}` names `{row['function']}` but "
            f"`{module_file.relative_to(root)}` declares no `fn {fn_name}` in "
            "production code",
        )
        return None
    if type_name is not None:
        declared = re.search(
            r"\b(struct|enum|union|trait)\s+" + re.escape(type_name) + r"\b", text
        )
        implemented = re.search(r"\bimpl\b[^\n{]*\b" + re.escape(type_name) + r"\b", text)
        if not declared and not implemented:
            report.violation(
                "row-type-absent",
                f"row `{row['invariant']}` names type `{type_name}` which "
                f"`{module_file.relative_to(root)}` neither declares nor implements",
            )
            return None
    return module_file


def run_checks(root: pathlib.Path, label: str, min_rows: int, min_crates: int, min_assumptions: int) -> Report:
    report = Report(label)
    rows = parse_rows(root, report)
    assumptions = parse_assumptions(root, report)
    markers = collect_markers(root)

    if not rows:
        report.violation("no-rows", "MAPPING.md parsed to zero rows; refusing to pass silently")
    if not markers:
        report.violation(
            "no-markers",
            "no `// INVARIANT:` marker found in any `crates/*/src`; refusing to pass silently",
        )
    if not assumptions:
        report.violation(
            "no-assumptions", "assumptions.toml parsed to zero assumptions; refusing to pass silently"
        )

    seen = set()
    for row in rows:
        if row["invariant"] in seen:
            report.violation("row-duplicate", f"row `{row['invariant']}` appears more than once")
        seen.add(row["invariant"])
        if not row["summary"]:
            report.violation(
                "row-no-summary", f"row `{row['invariant']}` states nothing in its last column"
            )

    row_by_name = {row["invariant"]: row for row in rows}

    # 1. Every marker has a row.
    marker_names = set()
    for name, source in markers:
        marker_names.add(name)
        if name not in row_by_name:
            report.violation(
                "marker-unmapped",
                f"`// INVARIANT: {name}` in {source.relative_to(root)} has no row in "
                f"{MAPPING_REL}",
            )

    # 2 and 3. Every row resolves, and its marker is in the file it resolves to.
    markers_by_name: dict[str, set[pathlib.Path]] = {}
    for name, source in markers:
        markers_by_name.setdefault(name, set()).add(source)
    for row in rows:
        module_file = check_row_resolves(root, row, report)
        if module_file is None:
            continue
        sources = markers_by_name.get(row["invariant"], set())
        if not sources:
            report.violation(
                "row-unmarked",
                f"row `{row['invariant']}` has no `// INVARIANT: {row['invariant']}` "
                "marker in any production source",
            )
        elif module_file not in sources:
            report.violation(
                "row-marker-elsewhere",
                f"row `{row['invariant']}` resolves to "
                f"{module_file.relative_to(root)} but its marker is only in "
                + ", ".join(sorted(str(s.relative_to(root)) for s in sources)),
            )

    # 4. Assumptions.
    declared_ids = set()
    for assumption in assumptions:
        identifier = assumption.get("id")
        if not identifier:
            report.violation("assumption-no-id", "an assumption carries no `id`")
            continue
        if identifier in declared_ids:
            report.violation("assumption-duplicate", f"assumption `{identifier}` is declared twice")
        declared_ids.add(identifier)
        if not (assumption.get("owner") or "").strip():
            report.violation("assumption-no-owner", f"assumption `{identifier}` names no owner")
        if not (assumption.get("statement") or "").strip():
            report.violation("assumption-no-statement", f"assumption `{identifier}` states nothing")
        listed = assumption.get("invariants")
        if listed is None:
            report.violation(
                "assumption-no-invariants-key",
                f"assumption `{identifier}` has no `invariants` key; an empty list must be "
                "written out, so that omitting it cannot read as 'nothing depends on this'",
            )
            continue
        expected = {row["invariant"] for row in rows if row["assumption"] == identifier}
        if set(listed) != expected:
            report.violation(
                "assumption-invariants-drift",
                f"assumption `{identifier}` lists {sorted(listed)} but MAPPING.md rows "
                f"naming it are {sorted(expected)}",
            )
        if not listed and not (assumption.get("no_dependent_invariants_reason") or "").strip():
            report.violation(
                "assumption-empty-unexplained",
                f"assumption `{identifier}` has no dependent invariants and no "
                "`no_dependent_invariants_reason`",
            )

    for row in rows:
        if row["assumption"] not in declared_ids:
            report.violation(
                "row-assumption-undeclared",
                f"row `{row['invariant']}` names assumption `{row['assumption']}`, which "
                f"{ASSUMPTIONS_REL} does not declare",
            )

    # 5. Coverage floors.
    if len(rows) < min_rows:
        report.violation(
            "coverage-rows",
            f"{len(rows)} rows, fewer than the required {min_rows}",
        )
    crates_covered = {row["function"].split("::", 1)[0] for row in rows}
    if len(crates_covered) < min_crates:
        report.violation(
            "coverage-crates",
            f"rows span {len(crates_covered)} crates ({sorted(crates_covered)}), fewer "
            f"than the required {min_crates}",
        )
    if len(assumptions) < min_assumptions:
        report.violation(
            "coverage-assumptions",
            f"{len(assumptions)} assumptions, fewer than the required {min_assumptions}",
        )

    return report


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------

CLEAN_SOURCE = """\
pub struct Gate;

impl Gate {
    // INVARIANT: FIXTURE-ONE
    pub fn evaluate(&self) -> bool {
        false
    }
}

// INVARIANT: FIXTURE-TWO
pub fn free_guard() -> bool {
    false
}

#[cfg(test)]
mod tests {
    // INVARIANT: NOT-A-REAL-MARKER
    pub fn only_in_tests() -> bool {
        true
    }
}
"""

CLEAN_MAPPING = """\
# fixture

| Invariant | Enforcing function | Assumption | What it refuses |
| --- | --- | --- | --- |
| `FIXTURE-ONE` | `fixture_crate::gate::Gate::evaluate` | `ASSUME-FIXTURE` | refuses the first thing |
| `FIXTURE-TWO` | `fixture_crate::gate::free_guard` | `ASSUME-FIXTURE` | refuses the second thing |
"""

CLEAN_ASSUMPTIONS = """\
schema_version = 1

[[assumption]]
id = "ASSUME-FIXTURE"
owner = "fixture-crate"
statement = "the fixture holds"
invariants = ["FIXTURE-ONE", "FIXTURE-TWO"]

[[assumption]]
id = "ASSUME-UNUSED"
owner = "fixture-crate"
statement = "nothing depends on this yet"
invariants = []
no_dependent_invariants_reason = "no row needs it"
"""


def build_fixture(base: pathlib.Path) -> pathlib.Path:
    root = base
    source_dir = root / "crates" / "fixture-crate" / "src"
    source_dir.mkdir(parents=True)
    (source_dir / "lib.rs").write_text("pub mod gate;\n", encoding="utf-8")
    (source_dir / "gate.rs").write_text(CLEAN_SOURCE, encoding="utf-8")
    assurance = root / "docs" / "assurance"
    assurance.mkdir(parents=True)
    (assurance / "MAPPING.md").write_text(CLEAN_MAPPING, encoding="utf-8")
    (assurance / "assumptions.toml").write_text(CLEAN_ASSUMPTIONS, encoding="utf-8")
    return root


def mutate(root: pathlib.Path, case: str) -> None:
    gate = root / "crates" / "fixture-crate" / "src" / "gate.rs"
    mapping = root / "docs" / "assurance" / "MAPPING.md"
    assumptions = root / "docs" / "assurance" / "assumptions.toml"

    if case == "unmapped_marker":
        # Inserted ABOVE the `#[cfg(test)]` block, so it lands in production
        # text. Appending it after the block would be truncated away by
        # `production_text` and the case would pass for the wrong reason -- which
        # is how the first cut of this fixture behaved, and why the self-test
        # asserts on the diagnostic CODE rather than merely on non-emptiness.
        gate.write_text(
            gate.read_text().replace(
                "#[cfg(test)]",
                "// INVARIANT: FIXTURE-ORPHAN\npub fn orphan() {}\n\n#[cfg(test)]",
            )
        )
    elif case == "row_function_absent":
        mapping.write_text(mapping.read_text().replace("Gate::evaluate", "Gate::evaluate_renamed"))
        gate.write_text(gate.read_text().replace("FIXTURE-ONE", "FIXTURE-ONE"))
    elif case == "row_module_absent":
        mapping.write_text(mapping.read_text().replace("fixture_crate::gate::free_guard", "fixture_crate::absent::free_guard"))
    elif case == "row_crate_absent":
        mapping.write_text(mapping.read_text().replace("fixture_crate::gate::free_guard", "absent_crate::gate::free_guard"))
    elif case == "row_type_absent":
        mapping.write_text(mapping.read_text().replace("gate::Gate::evaluate", "gate::Absent::evaluate"))
    elif case == "row_assumption_undeclared":
        mapping.write_text(mapping.read_text().replace("`ASSUME-FIXTURE` | refuses the second", "`ASSUME-GHOST` | refuses the second"))
        assumptions.write_text(assumptions.read_text().replace('invariants = ["FIXTURE-ONE", "FIXTURE-TWO"]', 'invariants = ["FIXTURE-ONE"]'))
    elif case == "assumption_no_owner":
        assumptions.write_text(assumptions.read_text().replace('owner = "fixture-crate"\nstatement = "the fixture holds"', 'owner = ""\nstatement = "the fixture holds"'))
    elif case == "assumption_names_absent_invariant":
        assumptions.write_text(assumptions.read_text().replace('invariants = ["FIXTURE-ONE", "FIXTURE-TWO"]', 'invariants = ["FIXTURE-ONE", "FIXTURE-TWO", "FIXTURE-GHOST"]'))
    elif case == "assumption_drops_a_row":
        assumptions.write_text(assumptions.read_text().replace('invariants = ["FIXTURE-ONE", "FIXTURE-TWO"]', 'invariants = ["FIXTURE-ONE"]'))
    elif case == "assumption_empty_unexplained":
        assumptions.write_text(assumptions.read_text().replace('no_dependent_invariants_reason = "no row needs it"\n', ""))
    elif case == "row_unmarked":
        gate.write_text(gate.read_text().replace("// INVARIANT: FIXTURE-TWO\n", ""))
    elif case == "row_marker_elsewhere":
        gate.write_text(gate.read_text().replace("// INVARIANT: FIXTURE-TWO\n", ""))
        other = root / "crates" / "fixture-crate" / "src" / "lib.rs"
        other.write_text(other.read_text() + "// INVARIANT: FIXTURE-TWO\npub fn decoy() {}\n")
    elif case == "function_only_under_cfg_test":
        gate.write_text(
            gate.read_text().replace(
                "// INVARIANT: FIXTURE-TWO\npub fn free_guard() -> bool {\n    false\n}\n",
                "// INVARIANT: FIXTURE-TWO\npub fn placeholder() -> bool {\n    false\n}\n",
            ).replace(
                "    pub fn only_in_tests() -> bool {",
                "    pub fn free_guard() -> bool {",
            )
        )
    else:
        raise AssertionError(f"unknown fixture case {case}")


SELF_TEST_CASES = {
    "unmapped_marker": "marker-unmapped",
    "row_function_absent": "row-function-absent",
    "row_module_absent": "row-path-unresolvable",
    "row_crate_absent": "row-path-unresolvable",
    "row_type_absent": "row-type-absent",
    "row_assumption_undeclared": "row-assumption-undeclared",
    "assumption_no_owner": "assumption-no-owner",
    "assumption_names_absent_invariant": "assumption-invariants-drift",
    "assumption_drops_a_row": "assumption-invariants-drift",
    "assumption_empty_unexplained": "assumption-empty-unexplained",
    "row_unmarked": "row-unmarked",
    "row_marker_elsewhere": "row-marker-elsewhere",
    "function_only_under_cfg_test": "row-function-absent",
}


def run_self_test() -> bool:
    ok = True
    with tempfile.TemporaryDirectory() as raw:
        base = pathlib.Path(raw)

        clean = build_fixture(base / "clean")
        report = run_checks(clean, "self-test/clean", min_rows=2, min_crates=1, min_assumptions=2)
        if report.violations:
            ok = False
            print("SELF-TEST FAILED: the clean fixture must pass, but reported:", file=sys.stderr)
            for code, message in report.violations:
                print(f"  [{code}] {message}", file=sys.stderr)

        for case, expected_code in SELF_TEST_CASES.items():
            root = build_fixture(base / case)
            mutate(root, case)
            report = run_checks(root, f"self-test/{case}", min_rows=2, min_crates=1, min_assumptions=2)
            if expected_code not in report.codes():
                ok = False
                print(
                    f"SELF-TEST FAILED: case `{case}` must report `{expected_code}`, got "
                    f"{sorted(report.codes()) or 'no violations at all'}",
                    file=sys.stderr,
                )

        # The coverage floors have to be falsifiable too, or they are three
        # numbers nothing ever compares against.
        root = build_fixture(base / "coverage")
        report = run_checks(root, "self-test/coverage", min_rows=12, min_crates=4, min_assumptions=8)
        for expected_code in ("coverage-rows", "coverage-crates", "coverage-assumptions"):
            if expected_code not in report.codes():
                ok = False
                print(
                    f"SELF-TEST FAILED: the coverage floors must report `{expected_code}` "
                    f"against a 2-row fixture, got {sorted(report.codes())}",
                    file=sys.stderr,
                )
    return ok


if not run_self_test():
    print("check-mapping self-test failed; refusing to scan the real tree", file=sys.stderr)
    raise SystemExit(1)

report = run_checks(REPO_ROOT, "repository", min_rows=12, min_crates=4, min_assumptions=8)
if report.violations:
    print(f"check-mapping: {len(report.violations)} violation(s)", file=sys.stderr)
    for code, message in report.violations:
        print(f"  [{code}] {message}", file=sys.stderr)
    raise SystemExit(1)

rows = parse_rows(REPO_ROOT, Report("count"))
assumptions = parse_assumptions(REPO_ROOT, Report("count"))
markers = collect_markers(REPO_ROOT)
crates = sorted({row["function"].split("::", 1)[0] for row in rows})
print(
    f"check-mapping OK: {len(rows)} invariant rows across {len(crates)} crates "
    f"({', '.join(crates)}), {len(markers)} source markers, "
    f"{len(assumptions)} assumptions; {len(SELF_TEST_CASES) + 3} self-test cases passed"
)
PY
