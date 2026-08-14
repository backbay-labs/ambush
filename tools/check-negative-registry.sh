#!/usr/bin/env bash
# Phase-285 negative-registry gate. Each test must invoke the repository's
# shared typed protocol, which owns real/mirror(None)/mirror(Broken) execution
# over one typed probe. Cargo discovery and execution are checked separately.
# This proves the registered differential; it cannot mechanically prove a
# handwritten mirror faithful for inputs outside the registered probe.
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
    function_attributes,
    function_has_conditional_owner,
    matching_brace,
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


def protocol_metadata(clean, test):
    body = clean[test.body_start:test.body_end + 1]
    starts = list(re.finditer(r"\bassert_registered_negative_case\s*!\s*\{", body))
    if len(starts) != 1:
        return f"found {len(starts)} typed protocol invocations; expected one"
    opening = body.find("{", starts[0].start())
    closing = matching_brace(body, opening)
    if closing is None:
        return "typed protocol invocation has no closing brace"
    invocation = body[opening + 1:closing]
    header = re.match(
        r"\s*case\s*:\s*(?P<case>[A-Z][A-Z0-9_]*)\s*,"
        r"\s*mutation\s*:\s*(?P<mutation>[A-Za-z_][A-Za-z0-9_]*)\s*,"
        r"\s*control\s*:\s*(?P<control>[A-Za-z_][A-Za-z0-9_]*::[A-Za-z_][A-Za-z0-9_]*)\s*,"
        r"\s*broken\s*:\s*(?P<broken>[A-Za-z_][A-Za-z0-9_]*::[A-Za-z_][A-Za-z0-9_]*)\s*,",
        invocation,
    )
    if header is None:
        return "typed protocol header is not exact case/mutation/control/broken metadata"
    labels = []
    depths = {"(": 0, "[": 0, "{": 0}
    closing = {")": "(", "]": "[", "}": "{"}
    for match in re.finditer(r"[(){}\[\]]|[A-Za-z_][A-Za-z0-9_]*\s*:", invocation):
        token = match.group(0)
        if token in depths:
            depths[token] += 1
        elif token in closing:
            opener = closing[token]
            depths[opener] = max(0, depths[opener] - 1)
        elif not any(depths.values()) and not invocation[match.end():].startswith(":"):
            labels.append(token.rstrip().removesuffix(":"))
    for field in ("probe", "outcome", "real", "mirror", "denied", "permitted"):
        if labels.count(field) != 1:
            return f"typed protocol has no unique `{field}` operation"
    return header.groupdict()


def listed_tests(output):
    tests = set()
    for line in output.splitlines():
        match = re.fullmatch(r"(?P<name>[A-Za-z0-9_:]+): test", line.strip())
        if match:
            tests.add(match.group("name"))
    return tests


def run_summary(output):
    matches = list(re.finditer(
        r"^test result: ok\. (?P<passed>\d+) passed; (?P<failed>\d+) failed; "
        r"(?P<ignored>\d+) ignored; (?P<measured>\d+) measured; "
        r"(?P<filtered>\d+) filtered out;",
        output,
        re.M,
    ))
    if len(matches) != 1:
        return None
    return {key: int(value) for key, value in matches[0].groupdict().items()}


def shared_protocol_imported(raw, clean):
    declarations = []
    pattern = re.compile(
        r"(?P<attrs>(?:#\s*\[[^\]]*\]\s*)*)"
        r"mod\s+negative_protocol\s*;"
    )
    for match in pattern.finditer(clean):
        if clean.count("{", 0, match.start()) != clean.count("}", 0, match.start()):
            continue
        raw_attrs = raw[match.start("attrs"):match.end("attrs")]
        paths = re.findall(r'#\s*\[\s*path\s*=\s*"([^"]+)"\s*\]', raw_attrs)
        declarations.append(paths)
    imports = [
        match for match in re.finditer(
            r"\buse\s+negative_protocol\s*::\s*assert_registered_negative_case\s*;",
            clean,
        )
        if clean.count("{", 0, match.start()) == clean.count("}", 0, match.start())
    ]
    return declarations == [["../../../tests/negative_protocol.rs"]] and len(imports) == 1


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
        if not shared_protocol_imported(raw, clean):
            report.violation("entry-protocol-import-drift", f"entry `{invariant}` does not import the repository shared protocol from its exact path")
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
        if function_has_conditional_owner(clean, test):
            report.violation("entry-test-cfg-disabled", f"entry `{invariant}` test `{test_name}` has disabling conditional attributes")

        broken = entry.get("broken_variant", "")
        if not broken:
            report.violation("entry-no-broken-variant", f"entry `{invariant}` has no broken_variant"); continue
        if not enum_variant_defined(clean, broken, (test.declaration_start, test.body_end + 1)):
            report.violation("entry-broken-variant-undefined", f"entry `{invariant}` mutation `{broken}` has no exact executable Enum::Variant definition outside its test")
        enum_name = broken.split("::", 1)[0]
        control_variant = f"{enum_name}::None"
        if not enum_variant_defined(clean, control_variant, (test.declaration_start, test.body_end + 1)):
            report.violation("entry-control-variant-undefined", f"entry `{invariant}` has no `{control_variant}` control")
        if re.search(r"\bmacro_rules\s*!?\s*assert_registered_negative_case\b", clean):
            report.violation("entry-protocol-shadowed", f"entry `{invariant}` test file locally redefines the shared protocol")
        metadata = protocol_metadata(clean, test)
        if isinstance(metadata, str):
            report.violation("entry-protocol-missing", f"entry `{invariant}`: {metadata}")
        else:
            case_type = entry.get("case_type", "")
            expected_case = invariant.replace("-", "_")
            if case_type != expected_case or metadata["case"] != expected_case:
                report.violation("entry-case-identity-drift", f"entry `{invariant}` case `{case_type}`, protocol `{metadata['case']}`, expected `{expected_case}`")
            if metadata["mutation"] != enum_name:
                report.violation("entry-mutation-type-drift", f"entry `{invariant}` protocol mutation `{metadata['mutation']}` != `{enum_name}`")
            if metadata["control"] != control_variant:
                report.violation("entry-control-variant-drift", f"entry `{invariant}` protocol control `{metadata['control']}` != `{control_variant}`")
            if metadata["broken"] != broken:
                report.violation("entry-broken-variant-drift", f"entry `{invariant}` protocol broken `{metadata['broken']}` != `{broken}`")

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
            discovery = subprocess.run(
                ["cargo", "test", "-p", crate, "--test", target, "--", "--list"],
                cwd=root,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            if discovery.returncode:
                report.violation("entry-test-list-failed", f"{crate}/{target} discovery failed:\n{discovery.stderr[-4000:]}")
                continue
            discovered = listed_tests(discovery.stdout)
            if discovered != names:
                report.violation("entry-test-list-drift", f"{crate}/{target} discovered {sorted(discovered)}, registry requires {sorted(names)}")
                continue
            result = subprocess.run(
                ["cargo", "test", "-p", crate, "--test", target],
                cwd=root,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            if result.returncode:
                report.violation("entry-test-target-failed", f"{crate}/{target} failed:\n{(result.stdout + result.stderr)[-4000:]}")
                continue
            summary = run_summary(result.stdout)
            if summary is None or summary != {"passed": len(names), "failed": 0, "ignored": 0, "measured": 0, "filtered": 0}:
                report.violation("entry-test-target-summary", f"{crate}/{target} did not prove exact {len(names)} passed, 0 failed/ignored/measured/filtered: {summary}")
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
#[path = "../../../tests/negative_protocol.rs"]
mod negative_protocol;
use negative_protocol::assert_registered_negative_case;

enum Mutation {
    None,
    RemoveGuard,
}
fn mirrored(mutation: Mutation) -> bool { matches!(mutation, Mutation::RemoveGuard) }
#[test]
fn broken_gate() {
    assert_registered_negative_case! {
        case: FIXTURE_ONE,
        mutation: Mutation,
        control: Mutation::None,
        broken: Mutation::RemoveGuard,
        probe: bool = true,
        outcome: bool,
        real: |_probe| Gate.evaluate(),
        mirror: |_probe, mutation| mirrored(mutation),
        denied: |value| !value,
        permitted: |value| *value,
    }
}
'''
REGISTRY = '''
schema_version=3
[[entry]]
invariant="FIXTURE-ONE"
case_type="FIXTURE_ONE"
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
    protocol = root / "tests"; protocol.mkdir()
    (protocol / "negative_protocol.rs").write_text("macro_rules! assert_registered_negative_case { ($($tokens:tt)*) => {} }\n")
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
    "comment_only_protocol": "entry-protocol-missing",
    "string_only_protocol": "entry-protocol-missing",
    "production_shaped_spoof": "entry-protocol-missing",
    "protocol_import_spoof": "entry-protocol-import-drift",
    "case_identity_drift": "entry-case-identity-drift",
    "broken_variant_drift": "entry-broken-variant-drift",
    "protocol_shadow": "entry-protocol-shadowed",
    "orphan": "entry-orphan",
    "unregistered": "row-unregistered",
    "ignored_test": "entry-test-ignored",
    "cfg_disabled_test": "entry-test-cfg-disabled",
    "module_cfg_disabled_test": "entry-test-cfg-disabled",
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
    elif case == "comment_only_protocol": test.write_text(test.read_text().replace("    assert_registered_negative_case! {", "    /* assert_registered_negative_case! {", 1).replace("    }\n}", "    } */\n}", 1))
    elif case == "string_only_protocol": test.write_text('#[test]\nfn broken_gate() { let _ = "assert_registered_negative_case! { case: FIXTURE_ONE }"; }\n')
    elif case == "production_shaped_spoof": test.write_text('''
enum Mutation { None, RemoveGuard }
fn mirrored(_: Mutation) -> bool { false }
#[test]
fn broken_gate() {
    let mirror = Gate;
    let _ = mirror.evaluate();
    std::hint::black_box(Mutation::None);
    std::hint::black_box(Mutation::RemoveGuard);
    assert!(!mirrored(Mutation::None));
    assert!(true);
}
''')
    elif case == "protocol_import_spoof": test.write_text(test.read_text().replace('../../../tests/negative_protocol.rs', 'alternate_protocol.rs'))
    elif case == "case_identity_drift": test.write_text(test.read_text().replace("case: FIXTURE_ONE", "case: FIXTURE_GHOST"))
    elif case == "broken_variant_drift": test.write_text(test.read_text().replace("broken: Mutation::RemoveGuard", "broken: Mutation::None"))
    elif case == "protocol_shadow": test.write_text("macro_rules! assert_registered_negative_case { ($($t:tt)*) => {} }\n" + test.read_text())
    elif case == "orphan": registry.write_text(registry.read_text().replace("FIXTURE-ONE", "FIXTURE-GHOST"))
    elif case == "unregistered": registry.write_text("schema_version=2\n")
    elif case == "ignored_test": test.write_text(test.read_text().replace("#[test]", "#[test]\n#[ignore]"))
    elif case == "cfg_disabled_test": test.write_text(test.read_text().replace("#[test]", "#[cfg(any())]\n#[test]"))
    elif case == "module_cfg_disabled_test": test.write_text("#[cfg(any())]\nmod disabled {\n" + test.read_text() + "\n}\n")


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
        spoofed_output = "\n".join((
            "test broken_gate ... ok",
            "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;",
            "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;",
        ))
        if listed_tests(spoofed_output) or run_summary(spoofed_output) is not None:
            ok = False
            print("negative self-test stdout spoof was accepted as Cargo discovery/execution evidence", file=sys.stderr)
    return ok


if not self_test(): raise SystemExit("check-negative-registry self-test failed")
report = run_checks(REPO_ROOT, execute_tests=True)
if report.violations:
    print(f"check-negative-registry: {len(report.violations)} violation(s)", file=sys.stderr)
    for code, message in report.violations: print(f"  [{code}] {message}", file=sys.stderr)
    raise SystemExit(1)
registered = entries(REPO_ROOT, Report())
print(f"check-negative-registry OK: {len(registered)} executable tests; {len(CASES)+2} self-tests passed (1 clean control, {len(CASES)+1} adversarial)")
PY
