#!/usr/bin/env bash
#
# Negative-falsifiability registry gate (FALSIFY-01, FALSIFY-03, FALSIFY-04;
# phase 285).
#
# WHY THIS EXISTS
#   `tools/check-mapping.sh` proves that every row of
#   `docs/assurance/MAPPING.md` names a function that exists. It cannot prove
#   that the function actually refuses anything: a row pointing at a `fn` whose
#   guard was deleted still resolves. What closes that is a test per row that
#   constructs a deliberately-broken variant of the function and asserts the
#   BROKEN variant permits what the real one refuses -- and this gate is what
#   makes such a test mandatory rather than customary.
#
# WHAT IS CHECKED
#   1. Every MAPPING.md row has exactly one entry in
#      `docs/assurance/negative-registry.toml`, and every entry names a
#      MAPPING.md row. Both directions, so neither file grows orphans.
#   2. `production_fn` equals the row's `Enforcing function` column exactly.
#      A registry that drifted from the table would be evidence about a
#      different function than the one the table claims.
#   3. `entry_point` names a `fn` that is declared in production code under
#      `crates/<crate>/src`, so a renamed public entry point is caught.
#   4. `test_file` exists, sits at `crates/*/tests/negative_*.rs`, and declares
#      `fn <test_fn>` carrying a `#[test]` or `#[tokio::test]` attribute. An
#      un-annotated function is not a test; cargo would never run it and
#      nothing else would say so.
#   5. `broken_variant` is named INSIDE the body of `test_fn` and is also
#      defined somewhere ELSE in the same file. That is what ties the named
#      mutation to the test that exercises it.
#   6. `permits` and `observed_when_neutralized` are non-empty. The second is
#      the record that the mutation was actually neutralized and the test
#      actually watched to fail.
#   7. At least 12 entries, matching the phase's coverage floor.
#
# WHAT IS NOT CHECKED, AND SAYING SO IS THE POINT
#   That `broken_variant` is a FAITHFUL copy of the function it mirrors with
#   exactly one guard removed. No static check can establish that, and claiming
#   otherwise would be the same defect this file exists to prevent. Two things
#   stand in for it: each test's unmutated control, which asserts the mirror
#   reproduces the real function's outcome on the same probe input, and review
#   -- which is why every entry names its mirror so a reviewer can diff it
#   against the source it copies.
#
# SELF-TEST
#   Every invocation first builds synthetic repositories in a temp directory and
#   runs the SAME checker over them: one clean tree that must pass, and thirteen
#   broken trees that must each be caught with the right diagnostic. If any case
#   misbehaves the script exits 1 WITHOUT looking at the real tree.
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
REGISTRY_REL = "docs/assurance/negative-registry.toml"
MIN_ENTRIES = 12

ROW = re.compile(
    r"^\|\s*`(?P<invariant>[A-Z0-9][A-Z0-9-]*)`\s*"
    r"\|\s*`(?P<function>[A-Za-z0-9_:]+)`\s*"
    r"\|\s*`(?P<assumption>[A-Z0-9][A-Z0-9-]*)`\s*"
    r"\|(?P<summary>[^|]*)\|\s*$",
    re.M,
)
TEST_FILE_SHAPE = re.compile(r"^crates/[^/]+/tests/negative_[A-Za-z0-9_]+\.rs$")
CFG_TEST_AT_COL0 = re.compile(r"^#\[cfg\(test\)\]", re.M)


class Report:
    def __init__(self) -> None:
        self.violations: list[tuple[str, str]] = []

    def violation(self, code: str, message: str) -> None:
        self.violations.append((code, message))

    def codes(self) -> set[str]:
        return {code for code, _ in self.violations}


def parse_rows(root: pathlib.Path, report: Report):
    path = root / MAPPING_REL
    if not path.is_file():
        report.violation("mapping-missing", f"{MAPPING_REL} does not exist")
        return []
    return [
        {"invariant": m.group("invariant"), "function": m.group("function")}
        for m in ROW.finditer(path.read_text(encoding="utf-8"))
    ]


def parse_entries(root: pathlib.Path, report: Report):
    path = root / REGISTRY_REL
    if not path.is_file():
        report.violation("registry-missing", f"{REGISTRY_REL} does not exist")
        return []
    try:
        document = tomllib.loads(path.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError as error:
        report.violation("registry-unparseable", f"{REGISTRY_REL}: {error}")
        return []
    return document.get("entry", [])


def function_body(text: str, name: str):
    """Body of `fn <name>`, by brace matching. None when not declared."""
    match = re.search(r"\bfn\s+" + re.escape(name) + r"\s*[(<]", text)
    if not match:
        return None
    opening = text.find("{", match.end())
    if opening == -1:
        return None
    depth = 0
    for index in range(opening, len(text)):
        if text[index] == "{":
            depth += 1
        elif text[index] == "}":
            depth -= 1
            if depth == 0:
                return text[opening : index + 1]
    return None


def has_test_attribute(text: str, name: str) -> bool:
    match = re.search(r"\bfn\s+" + re.escape(name) + r"\s*[(<]", text)
    if not match:
        return False
    preceding = text[: match.start()].rstrip()
    tail = preceding.splitlines()[-3:]
    return any(
        line.strip() in {"#[test]", "#[tokio::test]"} or line.strip().startswith("#[tokio::test(")
        for line in tail
    )


def production_declares_fn(root: pathlib.Path, crate_segment: str, fn_name: str) -> bool:
    crate_dir = root / "crates" / crate_segment.replace("_", "-") / "src"
    if not crate_dir.is_dir():
        return False
    pattern = re.compile(r"\bfn\s+" + re.escape(fn_name) + r"\s*[(<]")
    for source in crate_dir.glob("**/*.rs"):
        text = source.read_text(encoding="utf-8", errors="replace")
        match = CFG_TEST_AT_COL0.search(text)
        if match:
            text = text[: match.start()]
        if pattern.search(text):
            return True
    return False


def run_checks(root: pathlib.Path, min_entries: int) -> Report:
    report = Report()
    rows = parse_rows(root, report)
    entries = parse_entries(root, report)

    if not rows:
        report.violation("no-rows", "MAPPING.md parsed to zero rows; refusing to pass silently")
    if not entries:
        report.violation(
            "no-entries", f"{REGISTRY_REL} parsed to zero entries; refusing to pass silently"
        )

    row_by_name = {row["invariant"]: row for row in rows}

    seen: dict[str, int] = {}
    for entry in entries:
        invariant = entry.get("invariant")
        if not invariant:
            report.violation("entry-no-invariant", "a registry entry names no invariant")
            continue
        seen[invariant] = seen.get(invariant, 0) + 1

        row = row_by_name.get(invariant)
        if row is None:
            report.violation(
                "entry-orphan",
                f"registry entry `{invariant}` names no row in {MAPPING_REL}",
            )
            continue

        production_fn = entry.get("production_fn", "")
        if production_fn != row["function"]:
            report.violation(
                "entry-production-fn-drift",
                f"entry `{invariant}` names production_fn `{production_fn}` but the "
                f"MAPPING.md row names `{row['function']}`",
            )

        entry_point = entry.get("entry_point", "")
        if not entry_point:
            report.violation("entry-no-entry-point", f"entry `{invariant}` names no entry_point")
        else:
            segments = entry_point.split("::")
            if len(segments) < 2:
                report.violation(
                    "entry-point-malformed",
                    f"entry `{invariant}` entry_point `{entry_point}` is not a path",
                )
            elif not production_declares_fn(root, segments[0], segments[-1]):
                report.violation(
                    "entry-point-absent",
                    f"entry `{invariant}` entry_point `{entry_point}`: no `fn "
                    f"{segments[-1]}` is declared in production code under "
                    f"crates/{segments[0].replace('_', '-')}/src",
                )

        for field in ("permits", "observed_when_neutralized"):
            if not (entry.get(field) or "").strip():
                report.violation(
                    f"entry-empty-{field.replace('_', '-')}",
                    f"entry `{invariant}` has an empty `{field}`",
                )

        test_file = entry.get("test_file", "")
        if not TEST_FILE_SHAPE.match(test_file):
            report.violation(
                "entry-test-file-shape",
                f"entry `{invariant}` names `{test_file}`, which is not a "
                "`crates/*/tests/negative_*.rs` path",
            )
            continue
        path = root / test_file
        if not path.is_file():
            report.violation(
                "entry-test-file-absent", f"entry `{invariant}` names `{test_file}`, which does not exist"
            )
            continue
        text = path.read_text(encoding="utf-8")

        test_fn = entry.get("test_fn", "")
        body = function_body(text, test_fn) if test_fn else None
        if body is None:
            report.violation(
                "entry-test-fn-absent",
                f"entry `{invariant}` names test `{test_fn}`, which `{test_file}` does "
                "not declare",
            )
            continue
        if not has_test_attribute(text, test_fn):
            report.violation(
                "entry-test-fn-not-a-test",
                f"entry `{invariant}` names `{test_fn}`, which carries no `#[test]` or "
                "`#[tokio::test]` attribute, so cargo never runs it",
            )

        broken = entry.get("broken_variant", "")
        if not broken:
            report.violation("entry-no-broken-variant", f"entry `{invariant}` names no broken_variant")
            continue
        if not re.search(r"\b" + re.escape(broken) + r"\b", body):
            report.violation(
                "entry-broken-variant-unused",
                f"entry `{invariant}` names broken_variant `{broken}`, which the body of "
                f"`{test_fn}` never mentions",
            )
        outside = text.replace(body, "")
        if not re.search(r"\b" + re.escape(broken) + r"\b", outside):
            report.violation(
                "entry-broken-variant-undefined",
                f"entry `{invariant}` names broken_variant `{broken}`, which is not "
                f"defined anywhere else in `{test_file}`",
            )

    for invariant, count in seen.items():
        if count > 1:
            report.violation(
                "entry-duplicate", f"invariant `{invariant}` has {count} registry entries"
            )
    for row in rows:
        if row["invariant"] not in seen:
            report.violation(
                "row-unregistered",
                f"MAPPING.md row `{row['invariant']}` has no entry in {REGISTRY_REL}",
            )

    if len(entries) < min_entries:
        report.violation(
            "coverage-entries",
            f"{len(entries)} registry entries, fewer than the required {min_entries}",
        )
    return report


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------

FIXTURE_MAPPING = """\
| Invariant | Enforcing function | Assumption | What it refuses |
| --- | --- | --- | --- |
| `FIXTURE-ONE` | `fixture_crate::gate::Gate::evaluate` | `ASSUME-FIXTURE` | refuses the thing |
"""

FIXTURE_SOURCE = """\
pub struct Gate;

impl Gate {
    pub fn evaluate(&self) -> bool {
        false
    }
}
"""

FIXTURE_TEST = """\
fn broken_evaluate() -> bool {
    true
}

#[test]
fn broken_gate_permits_what_the_real_one_refuses() {
    assert!(!Gate.evaluate());
    assert!(broken_evaluate());
}
"""

FIXTURE_REGISTRY = """\
schema_version = 1

[[entry]]
invariant = "FIXTURE-ONE"
production_fn = "fixture_crate::gate::Gate::evaluate"
entry_point = "fixture_crate::gate::Gate::evaluate"
test_file = "crates/fixture-crate/tests/negative_gate.rs"
test_fn = "broken_gate_permits_what_the_real_one_refuses"
broken_variant = "broken_evaluate"
permits = "the thing the real gate refuses"
observed_when_neutralized = "left: false, right: true"
"""


def build_fixture(root: pathlib.Path) -> pathlib.Path:
    source_dir = root / "crates" / "fixture-crate" / "src"
    source_dir.mkdir(parents=True)
    (source_dir / "lib.rs").write_text("pub mod gate;\n", encoding="utf-8")
    (source_dir / "gate.rs").write_text(FIXTURE_SOURCE, encoding="utf-8")
    tests_dir = root / "crates" / "fixture-crate" / "tests"
    tests_dir.mkdir(parents=True)
    (tests_dir / "negative_gate.rs").write_text(FIXTURE_TEST, encoding="utf-8")
    assurance = root / "docs" / "assurance"
    assurance.mkdir(parents=True)
    (assurance / "MAPPING.md").write_text(FIXTURE_MAPPING, encoding="utf-8")
    (assurance / "negative-registry.toml").write_text(FIXTURE_REGISTRY, encoding="utf-8")
    return root


def mutate(root: pathlib.Path, case: str) -> None:
    registry = root / "docs" / "assurance" / "negative-registry.toml"
    mapping = root / "docs" / "assurance" / "MAPPING.md"
    test = root / "crates" / "fixture-crate" / "tests" / "negative_gate.rs"
    source = root / "crates" / "fixture-crate" / "src" / "gate.rs"

    if case == "row_unregistered":
        registry.write_text('schema_version = 1\n')
    elif case == "entry_orphan":
        registry.write_text(registry.read_text().replace('invariant = "FIXTURE-ONE"', 'invariant = "FIXTURE-GHOST"'))
    elif case == "entry_duplicate":
        registry.write_text(registry.read_text() + "\n" + registry.read_text().split("schema_version = 1\n", 1)[1])
    elif case == "production_fn_drift":
        registry.write_text(registry.read_text().replace('production_fn = "fixture_crate::gate::Gate::evaluate"', 'production_fn = "fixture_crate::gate::Gate::something_else"'))
    elif case == "entry_point_absent":
        registry.write_text(registry.read_text().replace('entry_point = "fixture_crate::gate::Gate::evaluate"', 'entry_point = "fixture_crate::gate::Gate::renamed"'))
    elif case == "test_file_absent":
        test.unlink()
    elif case == "test_file_shape":
        registry.write_text(registry.read_text().replace("tests/negative_gate.rs", "tests/gate.rs"))
    elif case == "test_fn_absent":
        registry.write_text(registry.read_text().replace('test_fn = "broken_gate_permits_what_the_real_one_refuses"', 'test_fn = "no_such_test"'))
    elif case == "test_fn_not_a_test":
        test.write_text(test.read_text().replace("#[test]\n", ""))
    elif case == "broken_variant_unused":
        test.write_text(test.read_text().replace("    assert!(broken_evaluate());\n", ""))
    elif case == "broken_variant_undefined":
        test.write_text(
            "#[test]\nfn broken_gate_permits_what_the_real_one_refuses() {\n"
            "    assert!(broken_evaluate());\n}\n"
        )
    elif case == "observed_empty":
        registry.write_text(registry.read_text().replace('observed_when_neutralized = "left: false, right: true"', 'observed_when_neutralized = "  "'))
    elif case == "permits_empty":
        registry.write_text(registry.read_text().replace('permits = "the thing the real gate refuses"', 'permits = ""'))
    elif case == "coverage":
        pass
    else:
        raise AssertionError(f"unknown fixture case {case}")
    _ = mapping, source


SELF_TEST_CASES = {
    "row_unregistered": "row-unregistered",
    "entry_orphan": "entry-orphan",
    "entry_duplicate": "entry-duplicate",
    "production_fn_drift": "entry-production-fn-drift",
    "entry_point_absent": "entry-point-absent",
    "test_file_absent": "entry-test-file-absent",
    "test_file_shape": "entry-test-file-shape",
    "test_fn_absent": "entry-test-fn-absent",
    "test_fn_not_a_test": "entry-test-fn-not-a-test",
    "broken_variant_unused": "entry-broken-variant-unused",
    "broken_variant_undefined": "entry-broken-variant-undefined",
    "observed_empty": "entry-empty-observed-when-neutralized",
    "permits_empty": "entry-empty-permits",
}


def run_self_test() -> bool:
    ok = True
    with tempfile.TemporaryDirectory() as raw:
        base = pathlib.Path(raw)

        clean = build_fixture(base / "clean")
        report = run_checks(clean, min_entries=1)
        if report.violations:
            ok = False
            print("SELF-TEST FAILED: the clean fixture must pass, but reported:", file=sys.stderr)
            for code, message in report.violations:
                print(f"  [{code}] {message}", file=sys.stderr)

        for case, expected_code in SELF_TEST_CASES.items():
            root = build_fixture(base / case)
            mutate(root, case)
            report = run_checks(root, min_entries=1)
            if expected_code not in report.codes():
                ok = False
                print(
                    f"SELF-TEST FAILED: case `{case}` must report `{expected_code}`, got "
                    f"{sorted(report.codes()) or 'no violations at all'}",
                    file=sys.stderr,
                )

        root = build_fixture(base / "coverage")
        report = run_checks(root, min_entries=MIN_ENTRIES)
        if "coverage-entries" not in report.codes():
            ok = False
            print(
                "SELF-TEST FAILED: the coverage floor must report `coverage-entries` against a "
                f"1-entry fixture, got {sorted(report.codes())}",
                file=sys.stderr,
            )
    return ok


if not run_self_test():
    print("check-negative-registry self-test failed; refusing to scan the real tree", file=sys.stderr)
    raise SystemExit(1)

report = run_checks(REPO_ROOT, MIN_ENTRIES)
if report.violations:
    print(f"check-negative-registry: {len(report.violations)} violation(s)", file=sys.stderr)
    for code, message in report.violations:
        print(f"  [{code}] {message}", file=sys.stderr)
    raise SystemExit(1)

entries = parse_entries(REPO_ROOT, Report())
files = sorted({entry.get("test_file", "") for entry in entries})
print(
    f"check-negative-registry OK: {len(entries)} entries across {len(files)} test files "
    f"({', '.join(pathlib.Path(f).name for f in files)}); "
    f"{len(SELF_TEST_CASES) + 2} self-test cases passed"
)
PY
