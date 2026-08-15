#!/usr/bin/env bash
# Phase-285 negative-registry gate. Each test must invoke the repository's
# shared typed protocol, which owns an exact production call plus
# mirror(None)/mirror(Broken) execution over one typed probe. A focused syn
# checker binds the entire registered test and shared protocol AST to local
# digests; Cargo discovery and execution independently prove the registered
# tests run. Those co-located digests are tamper-evident against uncoordinated
# edits, not an external trust anchor. Mirror fidelity beyond the registered
# probe remains a reviewed limitation.
set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

AST_TARGET_DIR="$ROOT_DIR/target/assurance-tools"
cargo build --quiet \
  --manifest-path "$ROOT_DIR/tools/negative-registry-ast/Cargo.toml" \
  --target-dir "$AST_TARGET_DIR"
export NEGATIVE_REGISTRY_AST="$AST_TARGET_DIR/debug/negative-registry-ast"

python3 - "$ROOT_DIR" <<'PY'
from __future__ import annotations

import pathlib
import re
import os
import shutil
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
UNIVERSE_REL = "docs/assurance/universe.toml"
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


def run_ast_checks(root, registered, report):
    lines = []
    binding_rows = []
    for entry in registered:
        relative = str(entry.get("test_file", ""))
        path = root / relative
        if not path.is_file():
            continue
        raw = path.read_text(encoding="utf-8", errors="replace")
        clean, _ = sanitize_rust(raw)
        test = test_function(clean, str(entry.get("test_fn", "")))
        if test is None:
            continue
        declaration = clean[test.declaration_start:test.body_start]
        macro_path = (
            "negative_protocol::assert_registered_async_negative_case"
            if re.search(r"\basync\s+fn\b", declaration)
            else "negative_protocol::assert_registered_negative_case"
        )
        edge_validation = str(entry.get("edge_validation", ""))
        fields = [
            str(entry.get("invariant", "")),
            relative,
            str(entry.get("test_fn", "")),
            str(entry.get("case_type", "")),
            str(entry.get("real_adapter", "")),
            str(entry.get("production_fn", "")),
            str(entry.get("production_entry", "")),
            str(entry.get("broken_variant", "")),
            macro_path,
            edge_validation,
        ]
        if any("\t" in field or "\n" in field for field in fields):
            report.violation("ast-contract-field", f"entry `{fields[0]}` has a non-scalar AST contract field")
            continue
        lines.append("\t".join(fields))
        binding_rows.append("|".join([
            str(entry.get("invariant", "")),
            str(entry.get("case_type", "")),
            str(entry.get("real_adapter", "")),
            str(entry.get("production_fn", "")),
            str(entry.get("production_entry", "")),
            str(entry.get("broken_variant", "")),
            macro_path,
            edge_validation,
        ]))
    if root.resolve() == REPO_ROOT.resolve():
        try:
            universe = tomllib.loads((root / UNIVERSE_REL).read_text())
        except (OSError, tomllib.TOMLDecodeError) as error:
            report.violation("universe-binding-read", str(error))
            universe = {}
        required = universe.get("required_bindings", [])
        if universe.get("schema_version") != 2:
            report.violation("universe-binding-schema", "universe must use schema_version = 2")
        if universe.get("binding_count") != len(binding_rows):
            report.violation("universe-binding-count", f"binding_count is not {len(binding_rows)}")
        if not isinstance(required, list) or len(required) != len(set(required)) or set(required) != set(binding_rows):
            report.violation("universe-binding-drift", "required_bindings is not the exact registry/source identity set")
    with tempfile.NamedTemporaryFile("w", suffix=".tsv", delete=False) as contract:
        contract.write("\n".join(lines) + "\n")
        contract_path = pathlib.Path(contract.name)
    try:
        mode = "--check" if root.resolve() == REPO_ROOT.resolve() else "--fixture"
        result = subprocess.run(
            [os.environ["NEGATIVE_REGISTRY_AST"], mode, str(contract_path)],
            cwd=root,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    finally:
        contract_path.unlink(missing_ok=True)
    if result.returncode:
        parsed = False
        for line in result.stderr.splitlines():
            match = re.fullmatch(r"\[([a-z0-9-]+)\]\s+(.*)", line)
            if match:
                parsed = True
                report.violation(match.group(1), match.group(2))
        if not parsed:
            report.violation("ast-check-failed", result.stderr[-4000:] or result.stdout[-4000:])


def run_checks(root, minimum=12, execute_tests=False):
    report = Report(); mapped = rows(root, report)
    document = registry_document(root, report); registered = document.get("entry", [])
    if document.get("schema_version") != 5:
        report.violation("registry-schema-version", "negative registry must use schema_version = 5")
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
        edge_validation = entry.get("edge_validation", "")
        reason = str(entry.get("reachability_reason", "")).strip()
        if reachability not in {"direct", "indirect"}:
            report.violation("entry-reachability-invalid", f"entry `{invariant}` reachability must be direct or indirect")
        if not reason:
            report.violation("entry-reachability-reason-empty", f"entry `{invariant}` has no reachability reason")
        if reachability == "direct" and production != production_entry:
            report.violation("entry-direct-path-drift", f"entry `{invariant}` says direct but production_fn != production_entry")
        if reachability == "indirect" and production == production_entry:
            report.violation("entry-indirect-path-vacuous", f"entry `{invariant}` says indirect but names the same internal and entry paths")
        expected_edge = "direct" if reachability == "direct" else "reviewed-boundary"
        if edge_validation != expected_edge:
            report.violation("entry-edge-validation-drift", f"entry `{invariant}` edge_validation `{edge_validation}` != `{expected_edge}`")
        if reachability == "indirect" and production_entry != "serde_json::from_value":
            report.violation("entry-indirect-unreviewed", f"entry `{invariant}` has an indirect boundary outside the explicit serde boundary")
        if edge_validation == "reviewed-boundary" and not str(entry.get("edge_review_reason", "")).strip():
            report.violation("entry-edge-review-reason-empty", f"entry `{invariant}` reviewed boundary has no reason")
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
        case_type = entry.get("case_type", "")
        expected_case = invariant.replace("-", "_")
        if case_type != expected_case:
            report.violation("entry-case-identity-drift", f"entry `{invariant}` case `{case_type}` != `{expected_case}`")
        real_adapter = entry.get("real_adapter", "")
        expected_adapter = f"{expected_case}::real"
        if real_adapter != expected_adapter:
            report.violation("entry-real-adapter-drift", f"entry `{invariant}` real_adapter `{real_adapter}` != `{expected_adapter}`")

    for invariant, count in seen.items():
        if count > 1: report.violation("entry-duplicate", f"entry `{invariant}` appears {count} times")
    for row in mapped:
        if row["invariant"] not in seen: report.violation("row-unregistered", f"row `{row['invariant']}` has no registry entry")
    if len(registered) < minimum: report.violation("coverage-entries", f"{len(registered)} entries < {minimum}")
    run_ast_checks(root, registered, report)
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

enum Mutation {
    None,
    RemoveGuard,
}
fn mirrored(mutation: Mutation) -> bool { matches!(mutation, Mutation::RemoveGuard) }
#[test]
fn broken_gate() {
    negative_protocol::assert_registered_negative_case! {
        case: FIXTURE_ONE,
        mutation: Mutation,
        control: Mutation::None,
        broken: Mutation::RemoveGuard,
        state: {},
        probe: bool = true,
        outcome: bool,
        real_probe: probe,
        production: fixture_crate::gate::Gate::evaluate,
        arguments: (&Gate),
        call: sync,
        normalize: |production_result| production_result,
        mirror: |_state, _probe, mutation| mirrored(mutation),
        denied: |value| !value,
        permitted: |value| *value,
    }
}
'''
REGISTRY = '''
schema_version=5
[[entry]]
invariant="FIXTURE-ONE"
case_type="FIXTURE_ONE"
real_adapter="FIXTURE_ONE::real"
production_fn="fixture_crate::gate::Gate::evaluate"
production_entry="fixture_crate::gate::Gate::evaluate"
entry_reachability="direct"
edge_validation="direct"
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
    "comment_only_protocol": "ast-source-parse",
    "string_only_protocol": "ast-macro-path",
    "production_shaped_spoof": "ast-source-binding",
    "protocol_import_spoof": "ast-protocol-module",
    "case_identity_drift": "ast-source-binding",
    "real_adapter_drift": "entry-real-adapter-drift",
    "real_adapter_uses_mirror": "ast-source-binding",
    "broken_variant_drift": "ast-source-binding",
    "protocol_shadow": "ast-reserved-binding",
    "sync_alias_shadow": "ast-reserved-binding",
    "async_alias_shadow": "ast-reserved-binding",
    "dead_closure": "ast-macro-placement",
    "if_false_wrapper": "ast-macro-placement",
    "normalizer_constant": "ast-invocation-parse",
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
enum Mutation { None, RemoveGuard }
struct Mirror;
impl Mirror { fn evaluate(&self) -> bool { true } }
fn mirrored(mutation: Mutation) -> bool { matches!(mutation, Mutation::RemoveGuard) }
#[test]
fn broken_gate() {
    negative_protocol::assert_registered_negative_case! {
        case: FIXTURE_ONE,
        mutation: Mutation,
        control: Mutation::None,
        broken: Mutation::RemoveGuard,
        state: {},
        probe: bool = true,
        outcome: bool,
        real_probe: probe,
        production: Mirror::evaluate,
        arguments: (&Mirror),
        call: sync,
        normalize: |production_result| production_result,
        mirror: |_state, _probe, mutation| mirrored(mutation),
        denied: |value| !value,
        permitted: |value| *value,
    }
}
''')
    elif case == "protocol_import_spoof": test.write_text(test.read_text().replace('../../../tests/negative_protocol.rs', 'alternate_protocol.rs'))
    elif case == "case_identity_drift": test.write_text(test.read_text().replace("case: FIXTURE_ONE", "case: FIXTURE_GHOST"))
    elif case == "real_adapter_drift": registry.write_text(registry.read_text().replace('real_adapter="FIXTURE_ONE::real"', 'real_adapter="FIXTURE_ONE::mirror"'))
    elif case == "real_adapter_uses_mirror": test.write_text(test.read_text().replace("production: fixture_crate::gate::Gate::evaluate", "production: mirrored"))
    elif case == "broken_variant_drift": test.write_text(test.read_text().replace("broken: Mutation::RemoveGuard", "broken: Mutation::None"))
    elif case == "protocol_shadow": test.write_text("macro_rules! assert_registered_negative_case { ($($t:tt)*) => {} }\n" + test.read_text())
    elif case == "sync_alias_shadow": test.write_text(test.read_text().replace(
        "mod negative_protocol;",
        "mod negative_protocol;\nuse negative_protocol::assert_registered_negative_case as canonical_case;\nmacro_rules! assert_registered_negative_case { ($($tokens:tt)*) => {{ if false { canonical_case! { $($tokens)* } } }}; }",
    ).replace("negative_protocol::assert_registered_negative_case!", "assert_registered_negative_case!"))
    elif case == "async_alias_shadow": test.write_text(test.read_text().replace(
        "mod negative_protocol;",
        "mod negative_protocol;\nuse negative_protocol::assert_registered_async_negative_case as canonical_async;\nmacro_rules! assert_registered_async_negative_case { ($($tokens:tt)*) => {{ if false { canonical_async! { $($tokens)* } } }}; }",
    ).replace("#[test]\nfn broken_gate()", "#[tokio::test]\nasync fn broken_gate()").replace(
        "negative_protocol::assert_registered_negative_case!", "assert_registered_async_negative_case!"
    ).replace("call: sync", "call: awaited"))
    elif case == "dead_closure": test.write_text(test.read_text().replace(
        "    negative_protocol::assert_registered_negative_case! {",
        "    let _dead = || { negative_protocol::assert_registered_negative_case! {",
    ).replace("    }\n}\n", "    } };\n}\n", 1))
    elif case == "if_false_wrapper": test.write_text(test.read_text().replace(
        "    negative_protocol::assert_registered_negative_case! {",
        "    if false { negative_protocol::assert_registered_negative_case! {",
    ).replace("    }\n}\n", "    } }\n}\n", 1))
    elif case == "normalizer_constant": test.write_text(test.read_text().replace(
        "normalize: |production_result| production_result",
        "normalize: |_production_result| false",
    ))
    elif case == "orphan": registry.write_text(registry.read_text().replace("FIXTURE-ONE", "FIXTURE-GHOST"))
    elif case == "unregistered": registry.write_text("schema_version=5\n")
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

    def run(source, contract_source=contract):
        protocol_path.write_text(source)
        (tests / "negative_protocol_contract.rs").write_text(contract_source)
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

    mirror = "mirror: |state, probe, mutation| state.mirror(probe, mutation),"
    denied = "denied: |outcome| outcome == &ContractOutcome::Denied,"
    permitted = "permitted: |outcome| outcome == &ContractOutcome::Permitted,"
    contract_mutations = {
        "contract_mirror_forced_none": contract.replace(
            mirror,
            "mirror: |state, probe, _mutation| state.mirror(probe, ContractMutation::None),",
            1,
        ),
        "contract_mirror_forced_broken": contract.replace(
            mirror,
            "mirror: |state, probe, _mutation| state.mirror(probe, ContractMutation::Broken),",
            1,
        ),
        "contract_denied_constant_true": contract.replace(
            denied, "denied: |_outcome| true,", 1
        ),
        "contract_permitted_constant_true": contract.replace(
            permitted, "permitted: |_outcome| true,", 1
        ),
        "contract_predicates_swapped": contract.replace(
            denied, "denied: |outcome| outcome == &ContractOutcome::Permitted,", 1
        ).replace(
            permitted, "permitted: |outcome| outcome == &ContractOutcome::Denied,", 1
        ),
        "contract_denied_vacuous_true": contract.replace(
            denied,
            "denied: |outcome| outcome == &ContractOutcome::Denied || true,",
            1,
        ),
        "contract_permitted_vacuous_false": contract.replace(
            permitted,
            "permitted: |outcome| outcome == &ContractOutcome::Permitted && false,",
            1,
        ),
    }
    for name, mutated_contract in contract_mutations.items():
        if mutated_contract == contract:
            ok = False
            print(f"actual contract mutation {name}: replacement did not match", file=sys.stderr)
            continue
        result = run(protocol, mutated_contract)
        output = result.stdout + result.stderr
        if result.returncode == 0 or "test result: FAILED" not in output:
            ok = False
            print(f"actual contract mutation {name} did not produce a compiled test failure:\n{output[-4000:]}", file=sys.stderr)
    return ok, len(mutations) + len(contract_mutations)


def registered_source_mutation_self_test(base):
    registered = entries(REPO_ROOT, Report())
    targets = sorted({entry["test_file"] for entry in registered})
    clean_root = base / "registered_source_clean"
    for relative in targets:
        destination = clean_root / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(REPO_ROOT / relative, destination)
    protocol_destination = clean_root / PROTOCOL_REL
    protocol_destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(REPO_ROOT / PROTOCOL_REL, protocol_destination)

    def contract_text(root, entry_overrides=None):
        entry_overrides = entry_overrides or {}
        lines = []
        for original in registered:
            entry = {**original, **entry_overrides.get(original["invariant"], {})}
            relative = entry["test_file"]
            raw = (root / relative).read_text()
            clean, _ = sanitize_rust(raw)
            test = test_function(clean, entry["test_fn"])
            declaration = clean[test.declaration_start:test.body_start]
            macro_path = (
                "negative_protocol::assert_registered_async_negative_case"
                if re.search(r"\basync\s+fn\b", declaration)
                else "negative_protocol::assert_registered_negative_case"
            )
            edge = entry["edge_validation"]
            lines.append("\t".join([
                entry["invariant"], relative, entry["test_fn"], entry["case_type"],
                entry["real_adapter"], entry["production_fn"], entry["production_entry"],
                entry["broken_variant"], macro_path, edge,
            ]))
        return "\n".join(lines) + "\n"

    def run(root, overrides=None, binary=None):
        contract = root / "contract.tsv"
        contract.write_text(contract_text(root, overrides))
        return subprocess.run(
            [binary or os.environ["NEGATIVE_REGISTRY_AST"], "--check", str(contract)],
            cwd=root,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

    clean = run(clean_root)
    if clean.returncode:
        print(f"registered source clean AST contract failed:\n{clean.stderr[-4000:]}", file=sys.stderr)
        return False, 0

    def wrap_first(source, keyword):
        marker = "negative_protocol::assert_registered_negative_case!"
        start = source.index(marker)
        clean, _ = sanitize_rust(source)
        opening = clean.index("{", start)
        closing = matching_brace(clean, opening)
        if closing is None:
            raise AssertionError("registered macro has no closing brace")
        prefix = "if false { " if keyword == "if-false" else "let _dead = || { "
        suffix = " }" if keyword == "if-false" else " };"
        return source[:start] + prefix + source[start:closing + 1] + suffix + source[closing + 1:]

    def wrap_first_async(source):
        marker = "negative_protocol::assert_registered_async_negative_case!"
        start = source.index(marker)
        clean, _ = sanitize_rust(source)
        opening = clean.index("{", start)
        closing = matching_brace(clean, opening)
        if closing is None:
            raise AssertionError("registered async macro has no closing brace")
        return (
            source[:start]
            + "async { "
            + source[start:closing + 1]
            + " }.await;"
            + source[closing + 1:]
        )

    def replace_after(source, marker, old, new):
        start = source.index(marker)
        replacement = source[start:].replace(old, new, 1)
        return source[:start] + replacement

    def mutate_deploy_decoy(source, replacements):
        case_start = source.index("case: POLICY_DEPLOY_DECOY_MIN_SEVERITY")
        start = source.rfind("negative_protocol::assert_registered_negative_case!", 0, case_start)
        clean, _ = sanitize_rust(source)
        opening = clean.index("{", start)
        closing = matching_brace(clean, opening)
        if closing is None:
            raise AssertionError("reviewer bypass macro has no closing brace")
        prefix, invocation, suffix = source[:start], source[start:closing + 1], source[closing + 1:]
        for old, new in replacements:
            if invocation.count(old) != 1:
                raise AssertionError(f"reviewer bypass replacement `{old}` is not exact")
            invocation = invocation.replace(old, new, 1)
        return prefix + invocation + suffix

    deploy_mirror = "MirroredStaticGate::from_config(config, mutation)"
    deploy_denied = 'denied: |value| value == "Deny/static.deploy_decoy_min_severity"'
    deploy_permitted = 'permitted: |value| value == "Allow/static.default_allow"'

    def deploy_decoy_full_gate_bypass(source):
        return mutate_deploy_decoy(source, (
            (deploy_mirror,
             "MirroredStaticGate::from_config(config, StaticMutation::None)"),
            (deploy_denied, "denied: |_value| true"),
            (deploy_permitted, "permitted: |_value| true"),
        ))

    def deploy_decoy_coordinated_bypass(source):
        return mutate_deploy_decoy(source, (
            (deploy_mirror,
             "MirroredStaticGate::from_config(config, { let _ = mutation; StaticMutation::None })"),
            (deploy_denied, "denied: |value| { let _ = value; true }"),
            (deploy_permitted, "permitted: |value| { let _ = value; true }"),
        ))

    def inject_protocol_executor(source, statement):
        marker = '{\n    assert!(!C::INVARIANT.is_empty(), "case invariant identity is empty");'
        if source.count(marker) != 1:
            raise AssertionError("shared protocol executor marker is not exact")
        return source.replace(marker, "{\n    " + statement + "\n    assert!(!C::INVARIANT.is_empty(), \"case invariant identity is empty\");", 1)

    policy = "crates/swarm-policy/tests/negative_policy_gates.rs"
    runtime = "crates/swarm-runtime/tests/negative_runtime_fail_closed.rs"
    mutations = {
        "dead_closure": (policy, lambda value: wrap_first(value, "dead"), "ast-macro-placement", None),
        "if_false": (policy, lambda value: wrap_first(value, "if-false"), "ast-macro-placement", None),
        "unreachable_return": (policy, lambda value: value.replace(
            "    negative_protocol::assert_registered_negative_case! {",
            "    return;\n    negative_protocol::assert_registered_negative_case! {",
            1,
        ), "ast-macro-placement", None),
        "if_true_return": (policy, lambda value: value.replace(
            "    negative_protocol::assert_registered_negative_case! {",
            "    if true { return; }\n    negative_protocol::assert_registered_negative_case! {",
            1,
        ), "ast-macro-placement", None),
        "match_return": (policy, lambda value: value.replace(
            "    negative_protocol::assert_registered_negative_case! {",
            "    match () { () => return }\n    negative_protocol::assert_registered_negative_case! {",
            1,
        ), "ast-macro-placement", None),
        "loop_return": (policy, lambda value: value.replace(
            "    negative_protocol::assert_registered_negative_case! {",
            "    loop { return; }\n    negative_protocol::assert_registered_negative_case! {",
            1,
        ), "ast-macro-placement", None),
        "block_return": (policy, lambda value: value.replace(
            "    negative_protocol::assert_registered_negative_case! {",
            "    { return; }\n    negative_protocol::assert_registered_negative_case! {",
            1,
        ), "ast-macro-placement", None),
        "question_mark_return": (policy, lambda value: value.replace(
            "fn broken_empty_ruleset_arm_permits_the_action_the_real_gate_fails_closed_on() {",
            "fn broken_empty_ruleset_arm_permits_the_action_the_real_gate_fails_closed_on() -> Result<(), ()> {\n    Ok::<(), ()>(())?;",
            1,
        ), "ast-macro-placement", None),
        "async_block_wrapper": (
            runtime,
            wrap_first_async,
            "ast-macro-placement",
            None,
        ),
        "protocol_identity_prefix_bypass": (
            PROTOCOL_REL,
            lambda value: inject_protocol_executor(
                value,
                'if !C::INVARIANT.starts_with("PROTOCOL_") { return case; }',
            ),
            "ast-protocol-semantic-drift",
            None,
        ),
        "protocol_explicit_production_id_bypass": (
            PROTOCOL_REL,
            lambda value: inject_protocol_executor(
                value,
                'if matches!(C::INVARIANT, "POLICY_DEPLOY_DECOY_MIN_SEVERITY" | "SPINE_CHAIN_SEQ_MONOTONIC") { return case; }',
            ),
            "ast-protocol-semantic-drift",
            None,
        ),
        "protocol_inverse_contract_set_bypass": (
            PROTOCOL_REL,
            lambda value: inject_protocol_executor(
                value,
                'if C::INVARIANT != "PROTOCOL_CONTRACT" { return case; }',
            ),
            "ast-protocol-semantic-drift",
            None,
        ),
        "protocol_type_name_bypass": (
            PROTOCOL_REL,
            lambda value: inject_protocol_executor(
                value,
                'if !std::any::type_name::<C>().contains("PROTOCOL_CONTRACT") { return case; }',
            ),
            "ast-protocol-semantic-drift",
            None,
        ),
        "protocol_unconditional_early_return": (
            PROTOCOL_REL,
            lambda value: inject_protocol_executor(value, "return case;"),
            "ast-protocol-semantic-drift",
            None,
        ),
        "protocol_real_role_skipped": (
            PROTOCOL_REL,
            lambda value: value.replace(
                "let real = case.real(&probe).await;",
                "let real = case.mirror(&probe, C::CONTROL).await;",
                1,
            ),
            "ast-protocol-semantic-drift",
            None,
        ),
        "protocol_control_role_skipped": (
            PROTOCOL_REL,
            lambda value: value.replace(
                "let control = case.mirror(&probe, C::CONTROL).await;",
                "let control = case.real(&probe).await;",
                1,
            ),
            "ast-protocol-semantic-drift",
            None,
        ),
        "protocol_broken_role_skipped": (
            PROTOCOL_REL,
            lambda value: value.replace(
                "let broken = case.mirror(&probe, C::BROKEN).await;",
                "let broken = case.mirror(&probe, C::CONTROL).await;",
                1,
            ),
            "ast-protocol-semantic-drift",
            None,
        ),
        "sync_alias_shadow": (policy, lambda value: value.replace(
            "mod negative_protocol;",
            "mod negative_protocol;\nuse negative_protocol::assert_registered_negative_case as canonical_case;\nmacro_rules! assert_registered_negative_case { ($($tokens:tt)*) => {{ if false { canonical_case! { $($tokens)* } } }}; }",
            1,
        ).replace("negative_protocol::assert_registered_negative_case!", "assert_registered_negative_case!", 1), "ast-reserved-binding", None),
        "async_alias_shadow": (runtime, lambda value: value.replace(
            "mod negative_protocol;",
            "mod negative_protocol;\nuse negative_protocol::assert_registered_async_negative_case as canonical_async;\nmacro_rules! assert_registered_async_negative_case { ($($tokens:tt)*) => {{ if false { canonical_async! { $($tokens)* } } }}; }",
            1,
        ).replace("negative_protocol::assert_registered_async_negative_case!", "assert_registered_async_negative_case!", 1), "ast-reserved-binding", None),
        "wrong_protocol_path": (policy, lambda value: value.replace(
            '../../../tests/negative_protocol.rs', 'alternate_protocol.rs', 1
        ), "ast-protocol-module", None),
        "normalizer_constant": (policy, lambda value: value.replace(
            "normalize: |production_result| outcome(&production_result)",
            "normalize: |production_result| { let _ = production_result; false }",
            1,
        ), "ast-expected-binding-drift", None),
        "normalizer_helper_constant": (policy, lambda value: value.replace(
            "fn outcome(result: &Result<PolicyDecision, ApprovalError>) -> String {",
            "fn outcome(result: &Result<PolicyDecision, ApprovalError>) -> String { let _ = result; return \"Deny/fabricated\".to_string();",
            1,
        ), "ast-normalizer-helper", None),
        "reviewer_deploy_decoy_full_gate_bypass": (
            policy,
            deploy_decoy_full_gate_bypass,
            "ast-invocation-parse",
            None,
        ),
        "mirror_forced_none": (
            policy,
            lambda value: mutate_deploy_decoy(value, ((
                deploy_mirror,
                "MirroredStaticGate::from_config(config, StaticMutation::None)",
            ),)),
            "ast-invocation-parse",
            None,
        ),
        "mirror_forced_broken": (
            policy,
            lambda value: mutate_deploy_decoy(value, ((
                deploy_mirror,
                "MirroredStaticGate::from_config(config, StaticMutation::SkipDeployDecoyMinimum)",
            ),)),
            "ast-invocation-parse",
            None,
        ),
        "denied_predicate_constant_true": (
            policy,
            lambda value: mutate_deploy_decoy(
                value, ((deploy_denied, "denied: |_value| true"),)
            ),
            "ast-invocation-parse",
            None,
        ),
        "permitted_predicate_constant_false": (
            policy,
            lambda value: mutate_deploy_decoy(
                value, ((deploy_permitted, "permitted: |_value| false"),)
            ),
            "ast-invocation-parse",
            None,
        ),
        "predicate_input_semantically_ignored": (
            policy,
            lambda value: mutate_deploy_decoy(
                value, ((deploy_denied, "denied: |value| { let _ = value; true }"),)
            ),
            "ast-expected-binding-drift",
            None,
        ),
        "predicates_swapped": (
            policy,
            lambda value: mutate_deploy_decoy(value, (
                (deploy_denied, 'denied: |value| value == "Allow/static.default_allow"'),
                (deploy_permitted, 'permitted: |value| value == "Deny/static.deploy_decoy_min_severity"'),
            )),
            "ast-expected-binding-drift",
            None,
        ),
        "denied_predicate_vacuous_true": (
            policy,
            lambda value: mutate_deploy_decoy(value, ((
                deploy_denied,
                'denied: |value| value == "Deny/static.deploy_decoy_min_severity" || true',
            ),)),
            "ast-expected-binding-drift",
            None,
        ),
        "permitted_predicate_vacuous_false": (
            policy,
            lambda value: mutate_deploy_decoy(value, ((
                deploy_permitted,
                'permitted: |value| value == "Allow/static.default_allow" && false',
            ),)),
            "ast-expected-binding-drift",
            None,
        ),
        "renamed_mirror_entry": (
            policy,
            lambda value: replace_after(
                value.replace("MirroredStaticGate", "RenamedStaticGate"),
                "case: POLICY_NULL_EVIDENCE_REFUSED",
                "production: swarm_policy::static_gate::StaticApprovalGate::evaluate",
                "production: RenamedStaticGate::evaluate",
            ),
            "ast-expected-binding-drift",
            None,
        ),
        "coordinated_production_entry_substitution": (
            policy,
            lambda value: replace_after(
                value,
                "case: POLICY_NULL_EVIDENCE_REFUSED",
                "production: swarm_policy::static_gate::StaticApprovalGate::evaluate",
                "production: MirroredStaticGate::evaluate",
            ),
            "ast-expected-binding-drift",
            {"POLICY-NULL-EVIDENCE-REFUSED": {
                "production_entry": "MirroredStaticGate::evaluate",
            }},
        ),
    }
    ok = True
    for name, (relative, mutate_source, expected_code, overrides) in mutations.items():
        root = base / f"registered_source_{name}"
        shutil.copytree(clean_root, root)
        path = root / relative
        path.write_text(mutate_source(path.read_text()))
        result = run(root, overrides)
        codes = set(re.findall(r"\[([a-z0-9-]+)\]", result.stderr))
        if result.returncode == 0 or expected_code not in codes:
            ok = False
            print(f"registered source mutation {name}: expected {expected_code}, got {sorted(codes)}\n{result.stderr[-2000:]}", file=sys.stderr)

    coordinated = base / "coordinated_baseline_mutation"
    shutil.copytree(clean_root, coordinated)
    helper = coordinated / "tools/negative-registry-ast"
    helper.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(
        REPO_ROOT / "tools/negative-registry-ast",
        helper,
        ignore=shutil.ignore_patterns("target"),
    )
    policy_path = coordinated / policy
    policy_path.write_text(deploy_decoy_coordinated_bypass(policy_path.read_text()))
    docs = coordinated / "docs/assurance"
    docs.mkdir(parents=True)
    shutil.copy2(REPO_ROOT / REGISTRY_REL, docs / "negative-registry.toml")
    shutil.copy2(REPO_ROOT / UNIVERSE_REL, docs / "universe.toml")
    registry_path = docs / "negative-registry.toml"
    registry_path.write_text(registry_path.read_text().replace(
        'observed_when_neutralized = "Neutralizing SkipDeployDecoyMinimum changes the broken verdict from Allow to Deny."',
        'observed_when_neutralized = "Coordinated attack claims the vacuous differential is valid."',
        1,
    ))
    universe_path = docs / "universe.toml"
    universe_path.write_text(
        universe_path.read_text() + "\n# coordinated semantic-baseline attack\n"
    )
    contract = coordinated / "contract.tsv"
    contract.write_text(contract_text(coordinated))
    cargo_command = [
        "cargo", "run", "--quiet", "--manifest-path", str(helper / "Cargo.toml"),
        "--target-dir", str(REPO_ROOT / "target/assurance-tools-selftest"), "--",
    ]
    emitted = subprocess.run(
        [*cargo_command, "--emit", str(contract)],
        cwd=coordinated,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if emitted.returncode:
        print(f"coordinated semantic baseline emit failed:\n{emitted.stderr[-4000:]}", file=sys.stderr)
        return False, len(mutations) + 1
    expected_path = helper / "src/expected-bindings.tsv"
    comments = "\n".join(
        line for line in expected_path.read_text().splitlines() if line.startswith("#")
    )
    expected_path.write_text(comments + "\n" + emitted.stdout)
    result = subprocess.run(
        [*cargo_command, "--check", str(contract)],
        cwd=coordinated,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if result.returncode == 0 or "[ast-expected-parse]" not in result.stderr:
        ok = False
        print(f"coordinated semantic baseline mutation bypassed pinned digest:\n{result.stderr[-4000:]}", file=sys.stderr)
    return ok, len(mutations) + 1


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
        source_ok, source_mutations = registered_source_mutation_self_test(base)
        ok = ok and protocol_ok and source_ok
    return ok, protocol_mutations + source_mutations


self_test_ok, protocol_mutations = self_test()
if not self_test_ok: raise SystemExit("check-negative-registry self-test failed")
report = run_checks(REPO_ROOT, execute_tests=True)
if report.violations:
    print(f"check-negative-registry: {len(report.violations)} violation(s)", file=sys.stderr)
    for code, message in report.violations: print(f"  [{code}] {message}", file=sys.stderr)
    raise SystemExit(1)
registered = entries(REPO_ROOT, Report())
print(f"check-negative-registry OK: {len(registered)} executable tests + {len(CONTRACT_TESTS)} protocol-contract tests; {len(CASES)+3+protocol_mutations} self-tests passed ({3} clean controls, {len(CASES)+protocol_mutations} adversarial)")
PY
