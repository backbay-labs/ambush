#!/usr/bin/env bash
# Phase-285 negative-registry gate. Evidence is parsed from executable Rust
# tokens after comments and literals are removed; raw token grep is forbidden.
set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

python3 - "$ROOT_DIR" <<'PY'
from __future__ import annotations

import pathlib
import re
import subprocess
import sys
import tempfile
import tomllib

REPO_ROOT = pathlib.Path(sys.argv[1])
sys.path.insert(0, str(REPO_ROOT / "tools"))
from assurance_source import (  # noqa: E402
    enum_variant_defined,
    assertion_count,
    binding_declared,
    call_used,
    function_attributes,
    mutation_used,
    resolve_function,
    sanitize_rust,
    test_function,
)

MAPPING_REL = "docs/assurance/MAPPING.md"
REGISTRY_REL = "docs/assurance/negative-registry.toml"
TEST_FILE = re.compile(r"^crates/[^/]+/tests/negative_[A-Za-z0-9_]+\.rs$")
ROW = re.compile(
    r"^\|\s*`(?P<invariant>[A-Z0-9][A-Z0-9-]*)`\s*"
    r"\|\s*`(?P<function>[A-Za-z0-9_:]+)`\s*\|",
    re.M,
)


class Report:
    def __init__(self): self.violations: list[tuple[str, str]] = []
    def violation(self, code, message): self.violations.append((code, message))
    def codes(self): return {code for code, _ in self.violations}


def rows(root, report):
    path = root / MAPPING_REL
    if not path.is_file(): report.violation("mapping-missing", f"{MAPPING_REL} missing"); return []
    return [{"invariant": m.group("invariant"), "function": m.group("function")} for m in ROW.finditer(path.read_text())]


def entries(root, report):
    path = root / REGISTRY_REL
    if not path.is_file(): report.violation("registry-missing", f"{REGISTRY_REL} missing"); return []
    try: return tomllib.loads(path.read_text()).get("entry", [])
    except tomllib.TOMLDecodeError as error:
        report.violation("registry-unparseable", str(error)); return []


def run_checks(root, minimum=12, execute_tests=False):
    report = Report(); mapped = rows(root, report); registered = entries(root, report)
    if not mapped: report.violation("no-rows", "mapping parsed to zero rows")
    if not registered: report.violation("no-entries", "registry parsed to zero entries")
    row_by_name = {row["invariant"]: row for row in mapped}
    seen = {}
    for entry in registered:
        invariant = entry.get("invariant", "")
        if not invariant: report.violation("entry-no-invariant", "entry has no invariant"); continue
        seen[invariant] = seen.get(invariant, 0) + 1
        row = row_by_name.get(invariant)
        if row is None:
            report.violation("entry-orphan", f"entry `{invariant}` has no mapping row"); continue
        production = entry.get("production_fn", "")
        if production != row["function"]:
            report.violation("entry-production-fn-drift", f"entry `{invariant}` production_fn `{production}` != `{row['function']}`")
        for label, path_value in (("production", production), ("entry-point", entry.get("entry_point", ""))):
            resolved = resolve_function(root, path_value) if path_value else "path is empty"
            if isinstance(resolved, str):
                report.violation(f"entry-{label}-path-unresolvable", f"entry `{invariant}` {label}: {resolved}")
        for field in ("permits", "observed_when_neutralized"):
            if not str(entry.get(field, "")).strip():
                report.violation(f"entry-empty-{field.replace('_', '-')}", f"entry `{invariant}` has empty {field}")

        relative = entry.get("test_file", "")
        if not TEST_FILE.fullmatch(relative):
            report.violation("entry-test-file-shape", f"entry `{invariant}` has invalid test_file `{relative}`"); continue
        path = root / relative
        if not path.is_file():
            report.violation("entry-test-file-absent", f"entry `{invariant}` test file missing"); continue
        raw = path.read_text(encoding="utf-8", errors="replace")
        clean, _ = sanitize_rust(raw)
        test_name = entry.get("test_fn", "")
        # Distinguish absent declarations from real functions Cargo will not run.
        from assurance_source import find_function
        declared = find_function(clean, test_name, None) if test_name else None
        test = test_function(clean, test_name) if test_name else None
        if declared is None:
            report.violation("entry-test-fn-absent", f"entry `{invariant}` test `{test_name}` has no executable function body"); continue
        if test is None:
            report.violation("entry-test-fn-not-a-test", f"entry `{invariant}` `{test_name}` lacks adjacent #[test] or #[tokio::test]"); continue
        attributes = function_attributes(clean, test)
        if any(attribute.startswith("ignore") for attribute in attributes):
            report.violation("entry-test-ignored", f"entry `{invariant}` test `{test_name}` is #[ignore]")
        if any(attribute.startswith("cfg(") or attribute.startswith("cfg_attr(") for attribute in attributes):
            report.violation("entry-test-cfg-disabled", f"entry `{invariant}` test `{test_name}` has disabling conditional attributes")
        if assertion_count(clean, test) < 2:
            report.violation("entry-test-no-assertions", f"entry `{invariant}` test `{test_name}` has fewer than two executable assertions")

        broken = entry.get("broken_variant", "")
        if not broken:
            report.violation("entry-no-broken-variant", f"entry `{invariant}` has no broken_variant"); continue
        if not enum_variant_defined(clean, broken, (test.declaration_start, test.body_end + 1)):
            report.violation("entry-broken-variant-undefined", f"entry `{invariant}` mutation `{broken}` has no exact executable Enum::Variant definition outside its test")
        if not mutation_used(clean, broken, test):
            report.violation("entry-broken-variant-unused", f"entry `{invariant}` mutation `{broken}` is not passed to a non-assertion call or constructor inside its test")
        enum_name = broken.split("::", 1)[0]
        control_variant = f"{enum_name}::None"
        if not enum_variant_defined(clean, control_variant, (test.declaration_start, test.body_end + 1)):
            report.violation("entry-control-variant-undefined", f"entry `{invariant}` has no `{control_variant}` control")
        elif not mutation_used(clean, control_variant, test):
            report.violation("entry-control-variant-unused", f"entry `{invariant}` does not drive `{control_variant}` through a mirror")
        entry_symbol = str(entry.get("entry_point", "")).rsplit("::", 1)[-1]
        real_symbol = "from_value" if entry_symbol == "try_from" else entry_symbol
        if not call_used(clean, real_symbol, test):
            report.violation("entry-real-call-missing", f"entry `{invariant}` test does not call real entry symbol `{real_symbol}`")
        if not binding_declared(clean, "real", test):
            report.violation("entry-real-binding-missing", f"entry `{invariant}` has no named real probe binding")
        if not binding_declared(clean, "control", test):
            report.violation("entry-control-binding-missing", f"entry `{invariant}` has no named control probe binding")
        if not binding_declared(clean, "broken", test):
            report.violation("entry-broken-binding-missing", f"entry `{invariant}` has no named broken probe binding")

    for invariant, count in seen.items():
        if count > 1: report.violation("entry-duplicate", f"entry `{invariant}` appears {count} times")
    for row in mapped:
        if row["invariant"] not in seen: report.violation("row-unregistered", f"row `{row['invariant']}` has no registry entry")
    if len(registered) < minimum: report.violation("coverage-entries", f"{len(registered)} entries < {minimum}")
    if execute_tests and not report.violations:
        targets = {}
        for entry in registered:
            relative = entry["test_file"]
            parts = pathlib.PurePosixPath(relative).parts
            crate = parts[1]
            target = pathlib.PurePosixPath(parts[-1]).stem
            targets.setdefault((crate, target), set()).add(entry["test_fn"])
        for (crate, target), names in sorted(targets.items()):
            result = subprocess.run(
                ["cargo", "test", "-p", crate, "--test", target, "--", "--nocapture"],
                cwd=root,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
            )
            output = result.stdout
            if result.returncode:
                report.violation("entry-test-target-failed", f"{crate}/{target} failed:\n{output[-4000:]}")
                continue
            for name in names:
                if re.search(r"^test\s+" + re.escape(name) + r"\s+\.\.\.\s+ok$", output, re.M) is None:
                    report.violation("entry-test-not-run", f"registered test `{name}` did not report ok in {crate}/{target}")
            summary = re.search(r"test result: ok\. (?P<passed>\d+) passed; 0 failed; (?P<ignored>\d+) ignored;", output)
            if summary is None or int(summary.group("ignored")) != 0:
                report.violation("entry-test-target-ignored", f"{crate}/{target} did not prove zero ignored tests")
    return report


MAPPING = '''
| Invariant | Enforcing function | Assumptions | What it refuses |
| --- | --- | --- | --- |
| `FIXTURE-ONE` | `fixture_crate::gate::Gate::evaluate` | `ASSUME-X` | danger |
'''
SOURCE = '''
pub struct Gate;
impl Gate { pub fn evaluate(&self) -> bool { false } }
'''
TEST = '''
enum Mutation {
    None,
    RemoveGuard,
}
fn mirrored(mutation: Mutation) -> bool { matches!(mutation, Mutation::RemoveGuard) }
#[test]
fn broken_gate() {
    let real = Gate.evaluate();
    assert!(!real);
    let control = mirrored(Mutation::None);
    assert!(!control);
    let broken = mirrored(Mutation::RemoveGuard);
    assert!(broken);
}
'''
REGISTRY = '''
schema_version=2
[[entry]]
invariant="FIXTURE-ONE"
production_fn="fixture_crate::gate::Gate::evaluate"
entry_point="fixture_crate::gate::Gate::evaluate"
test_file="crates/fixture-crate/tests/negative_gate.rs"
test_fn="broken_gate"
broken_variant="Mutation::RemoveGuard"
permits="danger"
observed_when_neutralized="assertion failed"
'''


def fixture(root):
    src = root / "crates/fixture-crate/src"; src.mkdir(parents=True)
    (src / "lib.rs").write_text("pub mod gate;\n"); (src / "gate.rs").write_text(SOURCE)
    tests = root / "crates/fixture-crate/tests"; tests.mkdir(parents=True)
    (tests / "negative_gate.rs").write_text(TEST)
    docs = root / "docs/assurance"; docs.mkdir(parents=True)
    (docs / "MAPPING.md").write_text(MAPPING); (docs / "negative-registry.toml").write_text(REGISTRY)
    return root


CASES = {
    "non_test_function": "entry-test-fn-not-a-test",
    "comment_only_test": "entry-test-fn-absent",
    "string_only_test": "entry-test-fn-absent",
    "nonexistent_module": "entry-entry-point-path-unresolvable",
    "nonexistent_type": "entry-entry-point-path-unresolvable",
    "comment_only_production": "entry-entry-point-path-unresolvable",
    "string_only_production": "entry-entry-point-path-unresolvable",
    "comment_only_mutation_definition": "entry-broken-variant-undefined",
    "string_only_mutation_definition": "entry-broken-variant-undefined",
    "comment_only_mutation_use": "entry-broken-variant-unused",
    "string_only_mutation_use": "entry-broken-variant-unused",
    "decorative_token_use": "entry-broken-variant-unused",
    "decorative_path_use": "entry-broken-variant-unused",
    "orphan": "entry-orphan",
    "unregistered": "row-unregistered",
    "ignored_test": "entry-test-ignored",
    "cfg_disabled_test": "entry-test-cfg-disabled",
    "black_box_only": "entry-test-no-assertions",
    "missing_real_call": "entry-real-call-missing",
    "missing_control_call": "entry-control-variant-unused",
    "missing_broken_call": "entry-broken-variant-unused",
}


def mutate(root, case):
    registry = root / "docs/assurance/negative-registry.toml"
    source = root / "crates/fixture-crate/src/gate.rs"
    test = root / "crates/fixture-crate/tests/negative_gate.rs"
    if case == "non_test_function": test.write_text(test.read_text().replace("#[test]\n", ""))
    elif case == "comment_only_test": test.write_text("/* #[test] fn broken_gate() { mirrored(Mutation::RemoveGuard); } */")
    elif case == "string_only_test": test.write_text('const X: &str = "#[test] fn broken_gate() { mirrored(Mutation::RemoveGuard); }";')
    elif case == "nonexistent_module": registry.write_text(registry.read_text().replace("::gate::Gate::evaluate\"\ntest_file", "::ghost::Gate::evaluate\"\ntest_file", 1))
    elif case == "nonexistent_type": registry.write_text(registry.read_text().replace("entry_point=\"fixture_crate::gate::Gate", "entry_point=\"fixture_crate::gate::Ghost"))
    elif case in {"comment_only_production", "string_only_production"}:
        registry.write_text(registry.read_text().replace("entry_point=\"fixture_crate::gate::Gate::evaluate\"", "entry_point=\"fixture_crate::gate::Gate::ghost\""))
        fake = "// pub fn ghost(&self) {}" if case.startswith("comment") else 'const X: &str = "pub fn ghost(&self) {}";'
        source.write_text(source.read_text() + "\n" + fake)
    elif case in {"comment_only_mutation_definition", "string_only_mutation_definition"}:
        test.write_text(test.read_text().replace("    RemoveGuard,", "    KeepGuard,").replace(
            "fn mirrored", ("// enum Fake { RemoveGuard }\nfn mirrored" if case.startswith("comment") else 'const X: &str = "enum Fake { RemoveGuard }";\nfn mirrored'), 1))
    elif case == "comment_only_mutation_use": test.write_text(test.read_text().replace("let broken = mirrored(Mutation::RemoveGuard);", "// mirrored(Mutation::RemoveGuard);\n    let broken = true;"))
    elif case == "string_only_mutation_use": test.write_text(test.read_text().replace("let broken = mirrored(Mutation::RemoveGuard);", 'let _ = "mirrored(Mutation::RemoveGuard)"; let broken = true;'))
    elif case == "decorative_token_use": test.write_text(test.read_text().replace("let broken = mirrored(Mutation::RemoveGuard);", "let RemoveGuard = 1; let _ = RemoveGuard; let broken = true;"))
    elif case == "decorative_path_use": test.write_text(test.read_text().replace("let broken = mirrored(Mutation::RemoveGuard);", "let _ = Mutation::RemoveGuard; let broken = true;"))
    elif case == "orphan": registry.write_text(registry.read_text().replace("FIXTURE-ONE", "FIXTURE-GHOST"))
    elif case == "unregistered": registry.write_text("schema_version=2\n")
    elif case == "ignored_test": test.write_text(test.read_text().replace("#[test]", "#[test]\n#[ignore]"))
    elif case == "cfg_disabled_test": test.write_text(test.read_text().replace("#[test]", "#[cfg(any())]\n#[test]"))
    elif case == "black_box_only":
        test.write_text(test.read_text().replace("assert!(!real);", "std::hint::black_box(real);").replace("assert!(!control);", "std::hint::black_box(control);").replace("assert!(broken);", "std::hint::black_box(broken);"))
    elif case == "missing_real_call": test.write_text(test.read_text().replace("Gate.evaluate()", "false"))
    elif case == "missing_control_call": test.write_text(test.read_text().replace("mirrored(Mutation::None)", "false"))
    elif case == "missing_broken_call": test.write_text(test.read_text().replace("mirrored(Mutation::RemoveGuard)", "true", 1))


def self_test():
    ok = True
    with tempfile.TemporaryDirectory() as raw:
        base = pathlib.Path(raw)
        clean = fixture(base / "clean"); report = run_checks(clean, 1)
        if report.violations: ok = False; print(f"negative self-test clean failed: {report.violations}", file=sys.stderr)
        for case, expected in CASES.items():
            root = fixture(base / case); mutate(root, case); codes = run_checks(root, 1).codes()
            if expected not in codes:
                ok = False; print(f"negative self-test {case}: expected {expected}, got {sorted(codes)}", file=sys.stderr)
    return ok


if not self_test(): raise SystemExit("check-negative-registry self-test failed")
report = run_checks(REPO_ROOT, execute_tests=True)
if report.violations:
    print(f"check-negative-registry: {len(report.violations)} violation(s)", file=sys.stderr)
    for code, message in report.violations: print(f"  [{code}] {message}", file=sys.stderr)
    raise SystemExit(1)
registered = entries(REPO_ROOT, Report())
print(f"check-negative-registry OK: {len(registered)} executable tests; {len(CASES)+1} self-tests passed (1 clean control, {len(CASES)} adversarial)")
PY
