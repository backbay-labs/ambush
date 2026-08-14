#!/usr/bin/env bash
# Phase-285 negative-registry gate. Each test must invoke the repository's
# shared typed protocol, which owns real/mirror(None)/mirror(Broken) execution
# over one typed probe. A separate compiled contract and mutations of the
# actual protocol source prove the role/count/assertion contract. Cargo
# discovery and execution are checked separately. This proves the registered
# operations. Entry binding is structural (an exact fully-qualified call in the
# named real adapter), not runtime instrumentation of the production function;
# mirror fidelity beyond the registered probe is reviewed, not mechanical.
set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

python3 - "$ROOT_DIR" <<'PY'
from __future__ import annotations

import pathlib
import re
import os
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
PROTOCOL_REL = "tests/negative_protocol.rs"
CONTRACT_REL = "crates/swarm-policy/tests/negative_protocol_contract.rs"
CONTRACT_CRATE = "swarm-policy"
CONTRACT_TARGET = "negative_protocol_contract"
CONTRACT_TESTS = {
    "protocol_executes_each_typed_role_exactly_once",
    "protocol_rejects_denying_broken",
    "protocol_rejects_permitting_real",
    "protocol_rejects_real_control_mismatch",
    "protocol_rejects_swapped_none_and_broken_roles",
}
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


def registry_document(root, report):
    path = root / REGISTRY_REL
    if not path.is_file(): report.violation("registry-missing", f"{REGISTRY_REL} missing"); return {}
    try: return tomllib.loads(path.read_text())
    except tomllib.TOMLDecodeError as error:
        report.violation("registry-unparseable", str(error)); return {}


def entries(root, report):
    return registry_document(root, report).get("entry", [])


def protocol_metadata(clean, test):
    body = clean[test.body_start:test.body_end + 1]
    starts = list(re.finditer(
        r"\b(?P<macro>assert_registered_(?:async_)?negative_case)\s*!\s*\{",
        body,
    ))
    if len(starts) != 1:
        return f"found {len(starts)} typed protocol invocations; expected one"
    opening = body.find("{", starts[0].start())
    closing = matching_brace(body, opening)
    if closing is None:
        return "typed protocol invocation has no closing brace"
    invocation = body[opening + 1:closing]
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
            labels.append((token.rstrip().removesuffix(":"), match.start(), match.end()))
    expected = [
        "case", "mutation", "control", "broken", "state", "probe", "outcome",
        "real", "mirror", "denied", "permitted",
    ]
    if [label for label, _, _ in labels] != expected:
        return f"typed protocol fields are not the exact ordered inventory {expected}"
    values = {}
    for index, (label, _start, end) in enumerate(labels):
        value_end = labels[index + 1][1] if index + 1 < len(labels) else len(invocation)
        values[label] = invocation[end:value_end].strip().rstrip(",").rstrip()
    exact = {
        "case": r"[A-Z][A-Z0-9_]*",
        "mutation": r"[A-Za-z_][A-Za-z0-9_]*",
        "control": r"[A-Za-z_][A-Za-z0-9_]*::[A-Za-z_][A-Za-z0-9_]*",
        "broken": r"[A-Za-z_][A-Za-z0-9_]*::[A-Za-z_][A-Za-z0-9_]*",
    }
    for label, pattern in exact.items():
        if re.fullmatch(pattern, values[label]) is None:
            return f"typed protocol `{label}` metadata is not exact"
    real = re.fullmatch(
        r"\|\s*(?P<state>[A-Za-z_][A-Za-z0-9_]*)\s*,\s*"
        r"(?P<probe>[A-Za-z_][A-Za-z0-9_]*)\s*\|\s*(?P<body>[\s\S]+)",
        values["real"],
    )
    mirror = re.fullmatch(
        r"\|\s*(?P<state>[A-Za-z_][A-Za-z0-9_]*)\s*,\s*"
        r"(?P<probe>[A-Za-z_][A-Za-z0-9_]*)\s*,\s*"
        r"(?P<mutation>[A-Za-z_][A-Za-z0-9_]*)\s*\|\s*(?P<body>[\s\S]+)",
        values["mirror"],
    )
    if real is None or mirror is None:
        return "typed protocol real/mirror operations are not typed adapter expressions"
    return {
        "macro": starts[0].group("macro"),
        "case": values["case"],
        "mutation": values["mutation"],
        "control": values["control"],
        "broken": values["broken"],
        "real_body": real.group("body"),
        "mirror_body": mirror.group("body"),
    }


def qualified_call_used(clean_expression, path):
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*(?:::[A-Za-z_][A-Za-z0-9_]*)+", path):
        return False
    qualified = r"\b" + r"\s*::\s*".join(re.escape(part) for part in path.split("::"))
    return re.search(qualified + r"(?:\s*::\s*<[^>{};]+>)?\s*\(", clean_expression) is not None


def real_adapter_uses_mirror(clean_expression):
    return re.search(r"\b(?:mirrored(?:_[A-Za-z0-9_]*)?|mirror)\s*\(", clean_expression) is not None


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


def shared_protocol_imported(raw, clean, macro_name):
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
    imports = []
    for match in re.finditer(r"\buse\s+negative_protocol\s*::(?P<body>[^;]+);", clean):
        if clean.count("{", 0, match.start()) == clean.count("}", 0, match.start()):
            imports.extend(re.findall(r"\bassert_registered_(?:async_)?negative_case\b", match.group("body")))
    return declarations == [["../../../tests/negative_protocol.rs"]] and imports.count(macro_name) == 1


def run_checks(root, minimum=12, execute_tests=False):
    report = Report(); mapped = rows(root, report)
    document = registry_document(root, report); registered = document.get("entry", [])
    if document.get("schema_version") != 4:
        report.violation("registry-schema-version", "negative registry must use schema_version = 4")
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
        production_entry = entry.get("production_entry", "")
        for label, path_value in (("production", production), ("production-entry", production_entry)):
            if label == "production-entry" and path_value == "serde_json::from_value":
                resolved = (pathlib.Path("external/serde_json"), None)
            else:
                resolved = resolve_function(root, path_value) if path_value else "path is empty"
            if isinstance(resolved, str):
                report.violation(f"entry-{label}-path-unresolvable", f"entry `{invariant}` {label}: {resolved}")
        reachability = entry.get("entry_reachability", "")
        reason = str(entry.get("reachability_reason", "")).strip()
        if reachability not in {"direct", "indirect"}:
            report.violation("entry-reachability-invalid", f"entry `{invariant}` reachability must be direct or indirect")
        if not reason:
            report.violation("entry-reachability-reason-empty", f"entry `{invariant}` has no reachability reason")
        if reachability == "direct" and production != production_entry:
            report.violation("entry-direct-path-drift", f"entry `{invariant}` says direct but production_fn != production_entry")
        if reachability == "indirect" and production == production_entry:
            report.violation("entry-indirect-path-vacuous", f"entry `{invariant}` says indirect but names the same internal and entry paths")
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
            if not shared_protocol_imported(raw, clean, metadata["macro"]):
                report.violation("entry-protocol-import-drift", f"entry `{invariant}` does not import `{metadata['macro']}` from the exact shared protocol path")
            case_type = entry.get("case_type", "")
            expected_case = invariant.replace("-", "_")
            if case_type != expected_case or metadata["case"] != expected_case:
                report.violation("entry-case-identity-drift", f"entry `{invariant}` case `{case_type}`, protocol `{metadata['case']}`, expected `{expected_case}`")
            real_adapter = entry.get("real_adapter", "")
            expected_adapter = f"{expected_case}::real"
            if real_adapter != expected_adapter:
                report.violation("entry-real-adapter-drift", f"entry `{invariant}` real_adapter `{real_adapter}` != `{expected_adapter}`")
            if metadata["mutation"] != enum_name:
                report.violation("entry-mutation-type-drift", f"entry `{invariant}` protocol mutation `{metadata['mutation']}` != `{enum_name}`")
            if metadata["control"] != control_variant:
                report.violation("entry-control-variant-drift", f"entry `{invariant}` protocol control `{metadata['control']}` != `{control_variant}`")
            if metadata["broken"] != broken:
                report.violation("entry-broken-variant-drift", f"entry `{invariant}` protocol broken `{metadata['broken']}` != `{broken}`")
            if not qualified_call_used(metadata["real_body"], production_entry):
                report.violation("entry-real-production-call-missing", f"entry `{invariant}` real adapter does not call exact production_entry `{production_entry}`")
            if real_adapter_uses_mirror(metadata["real_body"]):
                report.violation("entry-real-adapter-uses-mirror", f"entry `{invariant}` real adapter invokes mirror code")

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
        discovery = subprocess.run(
            ["cargo", "test", "-p", CONTRACT_CRATE, "--test", CONTRACT_TARGET, "--", "--list"],
            cwd=root,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if discovery.returncode:
            report.violation("protocol-contract-list-failed", f"protocol contract discovery failed:\n{discovery.stderr[-4000:]}")
        elif listed_tests(discovery.stdout) != CONTRACT_TESTS:
            report.violation("protocol-contract-list-drift", f"protocol contract discovered {sorted(listed_tests(discovery.stdout))}, expected {sorted(CONTRACT_TESTS)}")
        else:
            result = subprocess.run(
                ["cargo", "test", "-p", CONTRACT_CRATE, "--test", CONTRACT_TARGET],
                cwd=root,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            summary = run_summary(result.stdout)
            expected = {"passed": len(CONTRACT_TESTS), "failed": 0, "ignored": 0, "measured": 0, "filtered": 0}
            if result.returncode or summary != expected:
                report.violation("protocol-contract-execution-failed", f"protocol contract did not prove exact {expected}: {summary}\n{(result.stdout + result.stderr)[-4000:]}")
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
        state: {},
        probe: bool = true,
        outcome: bool,
        real: |_state, _probe| fixture_crate::gate::Gate::evaluate(&Gate),
        mirror: |_state, _probe, mutation| mirrored(mutation),
        denied: |value| !value,
        permitted: |value| *value,
    }
}
'''
REGISTRY = '''
schema_version=4
[[entry]]
invariant="FIXTURE-ONE"
case_type="FIXTURE_ONE"
real_adapter="FIXTURE_ONE::real"
production_fn="fixture_crate::gate::Gate::evaluate"
production_entry="fixture_crate::gate::Gate::evaluate"
entry_reachability="direct"
reachability_reason="The named adapter calls the public production entry."
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
    "nonexistent_module": "entry-production-entry-path-unresolvable",
    "nonexistent_type": "entry-production-entry-path-unresolvable",
    "comment_only_production": "entry-production-entry-path-unresolvable",
    "string_only_production": "entry-production-entry-path-unresolvable",
    "comment_only_mutation_definition": "entry-broken-variant-undefined",
    "string_only_mutation_definition": "entry-broken-variant-undefined",
    "comment_only_protocol": "entry-protocol-missing",
    "string_only_protocol": "entry-protocol-missing",
    "production_shaped_spoof": "entry-real-production-call-missing",
    "protocol_import_spoof": "entry-protocol-import-drift",
    "case_identity_drift": "entry-case-identity-drift",
    "real_adapter_drift": "entry-real-adapter-drift",
    "real_adapter_uses_mirror": "entry-real-adapter-uses-mirror",
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
    elif case == "nonexistent_module": registry.write_text(registry.read_text().replace("production_entry=\"fixture_crate::gate::Gate", "production_entry=\"fixture_crate::ghost::Gate"))
    elif case == "nonexistent_type": registry.write_text(registry.read_text().replace("production_entry=\"fixture_crate::gate::Gate", "production_entry=\"fixture_crate::gate::Ghost"))
    elif case in {"comment_only_production", "string_only_production"}:
        registry.write_text(registry.read_text().replace("production_entry=\"fixture_crate::gate::Gate::evaluate\"", "production_entry=\"fixture_crate::gate::Gate::ghost\""))
        fake = "// pub fn ghost(&self) {}" if case.startswith("comment") else 'const X: &str = "pub fn ghost(&self) {}";'
        source.write_text(source.read_text() + "\n" + fake)
    elif case in {"comment_only_mutation_definition", "string_only_mutation_definition"}:
        test.write_text(test.read_text().replace("    RemoveGuard,", "    KeepGuard,").replace(
            "fn mirrored", ("// enum Fake { RemoveGuard }\nfn mirrored" if case.startswith("comment") else 'const X: &str = "enum Fake { RemoveGuard }";\nfn mirrored'), 1))
    elif case == "comment_only_protocol": test.write_text(test.read_text().replace("    assert_registered_negative_case! {", "    /* assert_registered_negative_case! {", 1).replace("    }\n}", "    } */\n}", 1))
    elif case == "string_only_protocol": test.write_text('#[test]\nfn broken_gate() { let _ = "assert_registered_negative_case! { case: FIXTURE_ONE }"; }\n')
    elif case == "production_shaped_spoof": test.write_text('''
#[path = "../../../tests/negative_protocol.rs"]
mod negative_protocol;
use negative_protocol::assert_registered_negative_case;
enum Mutation { None, RemoveGuard }
struct Mirror;
impl Mirror { fn evaluate(&self) -> bool { true } }
fn mirrored(mutation: Mutation) -> bool { matches!(mutation, Mutation::RemoveGuard) }
#[test]
fn broken_gate() {
    let mirror = Gate;
    let _ = mirror.evaluate();
    std::hint::black_box(Mutation::None);
    std::hint::black_box(Mutation::RemoveGuard);
    assert!(!mirrored(Mutation::None));
    assert!(true);
    assert_registered_negative_case! {
        case: FIXTURE_ONE,
        mutation: Mutation,
        control: Mutation::None,
        broken: Mutation::RemoveGuard,
        state: {},
        probe: bool = true,
        outcome: bool,
        real: |_state, _probe| Mirror.evaluate(),
        mirror: |_state, _probe, mutation| mirrored(mutation),
        denied: |value| !value,
        permitted: |value| *value,
    }
}
''')
    elif case == "protocol_import_spoof": test.write_text(test.read_text().replace('../../../tests/negative_protocol.rs', 'alternate_protocol.rs'))
    elif case == "case_identity_drift": test.write_text(test.read_text().replace("case: FIXTURE_ONE", "case: FIXTURE_GHOST"))
    elif case == "real_adapter_drift": registry.write_text(registry.read_text().replace('real_adapter="FIXTURE_ONE::real"', 'real_adapter="FIXTURE_ONE::mirror"'))
    elif case == "real_adapter_uses_mirror": test.write_text(test.read_text().replace("fixture_crate::gate::Gate::evaluate(&Gate)", "mirrored(Mutation::None)"))
    elif case == "broken_variant_drift": test.write_text(test.read_text().replace("broken: Mutation::RemoveGuard", "broken: Mutation::None"))
    elif case == "protocol_shadow": test.write_text("macro_rules! assert_registered_negative_case { ($($t:tt)*) => {} }\n" + test.read_text())
    elif case == "orphan": registry.write_text(registry.read_text().replace("FIXTURE-ONE", "FIXTURE-GHOST"))
    elif case == "unregistered": registry.write_text("schema_version=4\n")
    elif case == "ignored_test": test.write_text(test.read_text().replace("#[test]", "#[test]\n#[ignore]"))
    elif case == "cfg_disabled_test": test.write_text(test.read_text().replace("#[test]", "#[cfg(any())]\n#[test]"))
    elif case == "module_cfg_disabled_test": test.write_text("#[cfg(any())]\nmod disabled {\n" + test.read_text() + "\n}\n")


def protocol_mutation_self_test(base):
    root = base / "actual_protocol_mutations"
    crate = root / "crates/protocol-contract"
    tests = crate / "tests"
    protocol_path = root / PROTOCOL_REL
    tests.mkdir(parents=True)
    protocol_path.parent.mkdir(parents=True, exist_ok=True)
    (root / "Cargo.toml").write_text(
        '[workspace]\nmembers = ["crates/protocol-contract"]\nresolver = "2"\n'
    )
    (crate / "Cargo.toml").write_text(
        '[package]\nname = "protocol-contract"\nversion = "0.0.0"\nedition = "2024"\n'
    )
    contract = (REPO_ROOT / CONTRACT_REL).read_text()
    protocol = (REPO_ROOT / PROTOCOL_REL).read_text()
    (tests / "negative_protocol_contract.rs").write_text(contract)

    command = ["cargo", "test", "--test", CONTRACT_TARGET]
    environment = {**os.environ, "CARGO_TARGET_DIR": str(root / "target")}

    def run(source):
        protocol_path.write_text(source)
        return subprocess.run(
            command,
            cwd=root,
            env=environment,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

    clean = run(protocol)
    if clean.returncode or run_summary(clean.stdout) != {
        "passed": len(CONTRACT_TESTS), "failed": 0, "ignored": 0,
        "measured": 0, "filtered": 0,
    }:
        print(f"actual protocol clean contract failed:\n{(clean.stdout + clean.stderr)[-4000:]}", file=sys.stderr)
        return False, 0

    sync_body = '''        let (case, probe) = $crate::negative_protocol::define_registered_negative_case! { $($tokens)* };
        let _completed_case =
            $crate::negative_protocol::execute_registered_negative_case_sync(case, probe);'''
    no_op = '''        let (_case, _probe) = $crate::negative_protocol::define_registered_negative_case! { $($tokens)* };'''
    if_false = '''        let (case, probe) = $crate::negative_protocol::define_registered_negative_case! { $($tokens)* };
        if false {
            let _completed_case =
                $crate::negative_protocol::execute_registered_negative_case_sync(case, probe);
        }'''
    equality = '''    assert_eq!(
        real, control,
        "the unmutated mirror drifted from the real denial"
    );'''
    permitted = '''    assert!(
        C::permitted(&broken),
        "removing the named guard did not permit"
    );'''
    mutations = {
        "macro_no_op": (sync_body, no_op),
        "macro_if_false": (sync_body, if_false),
        "omit_real_operation": (
            "    let real = case.real(&probe).await;",
            "    let real = case.mirror(&probe, C::CONTROL).await;",
        ),
        "omit_control_operation": (
            "    let control = case.mirror(&probe, C::CONTROL).await;",
            "    let control = case.real(&probe).await;",
        ),
        "omit_broken_operation": (
            "    let broken = case.mirror(&probe, C::BROKEN).await;",
            "    let broken = case.mirror(&probe, C::CONTROL).await;",
        ),
        "swap_control_broken_operations": (
            "    let control = case.mirror(&probe, C::CONTROL).await;\n    let broken = case.mirror(&probe, C::BROKEN).await;",
            "    let control = case.mirror(&probe, C::BROKEN).await;\n    let broken = case.mirror(&probe, C::CONTROL).await;",
        ),
        "remove_real_control_equality": (equality, ""),
        "invert_real_control_equality": (equality, equality.replace("assert_eq!", "assert_ne!")),
        "vacuous_real_control_equality": (equality, equality.replace("real, control", "real, real")),
        "remove_real_denial": (
            '    assert!(C::denied(&real), "the real operation did not deny");',
            "",
        ),
        "invert_real_denial": (
            '    assert!(C::denied(&real), "the real operation did not deny");',
            '    assert!(!C::denied(&real), "inverted real denial");',
        ),
        "remove_broken_permission": (permitted, ""),
        "invert_broken_permission": (
            permitted,
            permitted.replace("C::permitted(&broken)", "!C::permitted(&broken)"),
        ),
    }
    ok = True
    for name, (old, new) in mutations.items():
        count = protocol.count(old)
        if count != 1:
            ok = False
            print(f"actual protocol mutation {name}: replacement matched {count}, expected 1", file=sys.stderr)
            continue
        result = run(protocol.replace(old, new, 1))
        output = result.stdout + result.stderr
        if result.returncode == 0 or "test result: FAILED" not in output:
            ok = False
            print(f"actual protocol mutation {name} did not produce a compiled test failure:\n{output[-4000:]}", file=sys.stderr)
    return ok, len(mutations)


def self_test():
    ok = True
    protocol_mutations = 0
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
        protocol_ok, protocol_mutations = protocol_mutation_self_test(base)
        ok = ok and protocol_ok
    return ok, protocol_mutations


self_test_ok, protocol_mutations = self_test()
if not self_test_ok: raise SystemExit("check-negative-registry self-test failed")
report = run_checks(REPO_ROOT, execute_tests=True)
if report.violations:
    print(f"check-negative-registry: {len(report.violations)} violation(s)", file=sys.stderr)
    for code, message in report.violations: print(f"  [{code}] {message}", file=sys.stderr)
    raise SystemExit(1)
registered = entries(REPO_ROOT, Report())
print(f"check-negative-registry OK: {len(registered)} executable tests + {len(CONTRACT_TESTS)} protocol-contract tests; {len(CASES)+2+protocol_mutations} self-tests passed ({2} clean controls, {len(CASES)+protocol_mutations} adversarial)")
PY
