#!/usr/bin/env bash
# Phase-285 invariant-map gate. It uses a Rust lexical sanitizer so comments and
# literals cannot fabricate declarations, markers, or guard adjacency.
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
sys.path.insert(0, str(REPO_ROOT / "tools"))
from assurance_source import (  # noqa: E402
    function_spans,
    looks_like_executable_guard,
    next_code_line,
    production_sanitized,
    reachable_rust_files,
    resolve_function,
)

MAPPING_REL = "docs/assurance/MAPPING.md"
ASSUMPTIONS_REL = "docs/assurance/assumptions.toml"
OMISSIONS_REL = "docs/assurance/omissions.toml"
UNIVERSE_REL = "docs/assurance/universe.toml"
ROW = re.compile(
    r"^\|\s*`(?P<invariant>[A-Z0-9][A-Z0-9-]*)`\s*"
    r"\|\s*`(?P<function>[A-Za-z0-9_:]+)`\s*"
    r"\|(?P<assumptions>[^|]+)\|(?P<summary>[^|]*)\|\s*$",
    re.M,
)
MARKER = re.compile(r"^\s*INVARIANT:\s*(?P<name>[A-Z0-9][A-Z0-9-]*)\s*$")


class Report:
    def __init__(self): self.violations: list[tuple[str, str]] = []
    def violation(self, code, message): self.violations.append((code, message))
    def codes(self): return {code for code, _ in self.violations}


def load_toml(root, relative, key, report):
    path = root / relative
    if not path.is_file():
        report.violation(f"{key}-missing", f"{relative} does not exist")
        return []
    try:
        return tomllib.loads(path.read_text(encoding="utf-8")).get(key, [])
    except tomllib.TOMLDecodeError as error:
        report.violation(f"{key}-unparseable", f"{relative}: {error}")
        return []


def parse_rows(root, report):
    path = root / MAPPING_REL
    if not path.is_file():
        report.violation("mapping-missing", f"{MAPPING_REL} does not exist")
        return []
    rows = []
    for match in ROW.finditer(path.read_text(encoding="utf-8")):
        assumptions = re.findall(r"`(ASSUME-[A-Z0-9-]+)`", match.group("assumptions"))
        rows.append({
            "invariant": match.group("invariant"),
            "function": match.group("function"),
            "assumptions": assumptions,
            "summary": match.group("summary").strip(),
        })
    return rows


def collect_markers(root, crate_names):
    found = []
    for path in sorted(reachable_rust_files(root, crate_names)):
        raw = path.read_text(encoding="utf-8", errors="replace")
        clean, comments = production_sanitized(raw)
        spans = function_spans(clean)
        for comment in comments:
            match = MARKER.fullmatch(comment.text)
            if not match:
                continue
            next_line = next_code_line(clean, comment.start)
            owner = next(
                (span for span in spans if span.body_start < comment.start < span.body_end),
                None,
            )
            found.append({
                "name": match.group("name"), "path": path, "position": comment.start,
                "next_line": next_line, "owner": owner,
            })
    return found


def run_checks(root, min_rows=12, min_crates=4, min_assumptions=8):
    report = Report()
    rows = parse_rows(root, report)
    assumptions = load_toml(root, ASSUMPTIONS_REL, "assumption", report)
    omissions = load_toml(root, OMISSIONS_REL, "omission", report)
    universe_path = root / UNIVERSE_REL
    if not universe_path.is_file():
        report.violation("universe-missing", f"{UNIVERSE_REL} does not exist")
        universe = {}
    else:
        try: universe = tomllib.loads(universe_path.read_text(encoding="utf-8"))
        except tomllib.TOMLDecodeError as error:
            report.violation("universe-unparseable", f"{UNIVERSE_REL}: {error}"); universe = {}
    marker_crates = {row["function"].split("::", 1)[0].replace("_", "-") for row in rows}
    markers = collect_markers(root, marker_crates)
    if not rows: report.violation("no-rows", "MAPPING.md parsed to zero rows")
    if not markers: report.violation("no-markers", "no lexical INVARIANT markers found")

    row_by_name = {}
    for row in rows:
        name = row["invariant"]
        if name in row_by_name: report.violation("row-duplicate", f"row `{name}` is duplicated")
        row_by_name[name] = row
        if not row["summary"]: report.violation("row-no-summary", f"row `{name}` has no summary")
        if not row["assumptions"]:
            report.violation("row-no-assumptions", f"row `{name}` names no assumption")
        if len(set(row["assumptions"])) != len(row["assumptions"]):
            report.violation("row-assumption-duplicate", f"row `{name}` repeats an assumption")

    marker_by_name = {}
    for marker in markers:
        marker_by_name.setdefault(marker["name"], []).append(marker)
        relative = marker["path"].relative_to(root)
        if marker["name"] not in row_by_name:
            report.violation("marker-unmapped", f"{relative}: marker `{marker['name']}` has no row")
        if marker["owner"] is None:
            report.violation("marker-outside-function", f"{relative}: marker `{marker['name']}` is outside a function body")
        if marker["next_line"] is None or not looks_like_executable_guard(marker["next_line"][1]):
            got = "end of file" if marker["next_line"] is None else repr(marker["next_line"][1])
            report.violation("marker-not-on-guard", f"{relative}: marker `{marker['name']}` is followed by {got}, not an executable decision")

    for row in rows:
        resolved = resolve_function(root, row["function"])
        if isinstance(resolved, str):
            report.violation("row-path-unresolvable", f"row `{row['invariant']}`: {resolved}")
            continue
        path, span = resolved
        matching = marker_by_name.get(row["invariant"], [])
        if len(matching) != 1:
            report.violation("row-marker-count", f"row `{row['invariant']}` has {len(matching)} lexical source markers; expected one")
            continue
        marker = matching[0]
        if marker["path"] != path or not (span.body_start < marker["position"] < span.body_end):
            report.violation("row-marker-wrong-function", f"row `{row['invariant']}` marker is not inside exact `{row['function']}` body")

    declared = {}
    for assumption in assumptions:
        identifier = assumption.get("id", "")
        if not identifier:
            report.violation("assumption-no-id", "an assumption has no id"); continue
        if identifier in declared: report.violation("assumption-duplicate", f"assumption `{identifier}` is duplicated")
        declared[identifier] = assumption
        for field in ("owner", "statement", "holds_because", "breaks_if"):
            if not str(assumption.get(field, "")).strip():
                report.violation(f"assumption-no-{field.replace('_', '-')}", f"assumption `{identifier}` has no {field}")
        listed = assumption.get("invariants")
        if not isinstance(listed, list):
            report.violation("assumption-no-invariants", f"assumption `{identifier}` has no invariants list"); continue
        expected = {row["invariant"] for row in rows if identifier in row["assumptions"]}
        if set(listed) != expected:
            report.violation("assumption-invariants-drift", f"assumption `{identifier}` lists {sorted(set(listed))}, mapping requires {sorted(expected)}")
        if not listed and not str(assumption.get("no_dependent_invariants_reason", "")).strip():
            report.violation("assumption-empty-unexplained", f"assumption `{identifier}` has no dependents or reason")
    for row in rows:
        for identifier in row["assumptions"]:
            if identifier not in declared:
                report.violation("row-assumption-undeclared", f"row `{row['invariant']}` names undeclared `{identifier}`")

    omission_ids = set()
    omission_by_id = {}
    for omission in omissions:
        identifier = omission.get("id", "")
        if not identifier:
            report.violation("omission-no-id", "an omission has no id"); continue
        if identifier in omission_ids: report.violation("omission-duplicate", f"omission `{identifier}` is duplicated")
        omission_ids.add(identifier)
        omission_by_id[identifier] = omission
        for field in ("owner", "reason", "clearing_condition"):
            if not str(omission.get(field, "")).strip():
                report.violation(f"omission-no-{field.replace('_', '-')}", f"omission `{identifier}` has no {field}")
        path = omission.get("production_fn", "")
        resolved = resolve_function(root, path) if path else "no production_fn"
        if isinstance(resolved, str):
            report.violation("omission-path-unresolvable", f"omission `{identifier}`: {resolved}")

    required_invariants = universe.get("required_invariants", [])
    required_omissions = universe.get("required_omissions", [])
    if not isinstance(required_invariants, list) or not required_invariants:
        report.violation("universe-invariants-empty", "universe has no required_invariants")
        required_invariants = []
    if not isinstance(required_omissions, list) or not required_omissions:
        report.violation("universe-omissions-empty", "universe has no required_omissions")
        required_omissions = []
    required_invariant_set = set(required_invariants)
    required_omission_set = set(required_omissions)
    if len(required_invariants) != len(required_invariant_set):
        report.violation("universe-invariant-duplicate", "required_invariants contains duplicates")
    if len(required_omissions) != len(required_omission_set):
        report.violation("universe-omission-duplicate", "required_omissions contains duplicates")
    if required_invariant_set & required_omission_set:
        report.violation("universe-mapped-omitted-overlap", "an ID is both mapped and omitted")
    if set(row_by_name) != required_invariant_set:
        report.violation("universe-invariant-drift", f"mapping IDs {sorted(row_by_name)} != immutable universe {sorted(required_invariant_set)}")
    if omission_ids != required_omission_set:
        report.violation("universe-omission-drift", f"omission IDs {sorted(omission_ids)} != immutable universe {sorted(required_omission_set)}")
    if universe.get("invariant_count") != len(required_invariant_set):
        report.violation("universe-invariant-count", "invariant_count does not equal exact required set")
    if universe.get("omission_count") != len(required_omission_set):
        report.violation("universe-omission-count", "omission_count does not equal exact required set")

    surface_invariants: list[str] = []
    surface_omissions: list[str] = []
    for surface in universe.get("surface", []):
        surface_id = surface.get("id", "")
        prefixes = surface.get("production_prefixes", [])
        if not surface_id or not prefixes:
            report.violation("universe-surface-incomplete", f"surface `{surface_id}` lacks id or prefixes")
        for identifier in surface.get("invariants", []):
            surface_invariants.append(identifier)
            row = row_by_name.get(identifier)
            if row and not any(row["function"].startswith(prefix) for prefix in prefixes):
                report.violation("universe-surface-path", f"row `{identifier}` is outside surface `{surface_id}` prefixes")
        for identifier in surface.get("omissions", []):
            surface_omissions.append(identifier)
            omission = omission_by_id.get(identifier)
            if omission and not any(str(omission.get("production_fn", "")).startswith(prefix) for prefix in prefixes):
                report.violation("universe-surface-path", f"omission `{identifier}` is outside surface `{surface_id}` prefixes")
    if len(surface_invariants) != len(set(surface_invariants)) or set(surface_invariants) != required_invariant_set:
        report.violation("universe-surface-invariant-drift", "surface invariant assignments are not an exact one-to-one partition")
    if len(surface_omissions) != len(set(surface_omissions)) or set(surface_omissions) != required_omission_set:
        report.violation("universe-surface-omission-drift", "surface omission assignments are not an exact one-to-one partition")

    if len(rows) < min_rows: report.violation("coverage-rows", f"{len(rows)} rows < {min_rows}")
    crates = {row["function"].split("::", 1)[0] for row in rows}
    if len(crates) < min_crates: report.violation("coverage-crates", f"{len(crates)} crates < {min_crates}")
    if len(assumptions) < min_assumptions: report.violation("coverage-assumptions", f"{len(assumptions)} assumptions < {min_assumptions}")
    return report


SOURCE = '''
pub struct Gate;
impl Gate {
    pub fn evaluate(&self) -> bool {
        // INVARIANT: FIXTURE-ONE
        if dangerous() { return false; }
        true
    }
}
pub fn omitted() { if dangerous() {} }
#[cfg(test)] mod tests { pub fn fake() {} }
'''
MAPPING = '''
| Invariant | Enforcing function | Assumptions | What it refuses |
| --- | --- | --- | --- |
| `FIXTURE-ONE` | `fixture_crate::gate::Gate::evaluate` | `ASSUME-A`, `ASSUME-B` | danger |
'''
ASSUMPTIONS = '''
schema_version=2
[[assumption]]
id="ASSUME-A"
owner="x"
statement="s"
holds_because="h"
breaks_if="b"
invariants=["FIXTURE-ONE"]
[[assumption]]
id="ASSUME-B"
owner="x"
statement="s"
holds_because="h"
breaks_if="b"
invariants=["FIXTURE-ONE"]
'''
OMISSIONS = '''
schema_version=1
[[omission]]
id="OMIT-X"
production_fn="fixture_crate::gate::omitted"
owner="x"
reason="not a verdict"
clearing_condition="when it becomes one"
'''
UNIVERSE = '''
schema_version=1
invariant_count=1
omission_count=1
required_invariants=["FIXTURE-ONE"]
required_omissions=["OMIT-X"]
[[surface]]
id="fixture"
production_prefixes=["fixture_crate::"]
invariants=["FIXTURE-ONE"]
omissions=["OMIT-X"]
'''


def fixture(root):
    source = root / "crates/fixture-crate/src"; source.mkdir(parents=True)
    (source / "lib.rs").write_text("pub mod gate;\n")
    (source / "gate.rs").write_text(SOURCE)
    docs = root / "docs/assurance"; docs.mkdir(parents=True)
    (docs / "MAPPING.md").write_text(MAPPING)
    (docs / "assumptions.toml").write_text(ASSUMPTIONS)
    (docs / "omissions.toml").write_text(OMISSIONS)
    (docs / "universe.toml").write_text(UNIVERSE)
    return root


CASES = {
    "comment_fake_marker": "row-marker-count",
    "string_fake_marker": "row-marker-count",
    "comment_fake_function": "row-path-unresolvable",
    "string_fake_function": "row-path-unresolvable",
    "marker_not_adjacent": "marker-not-on-guard",
    "marker_wrong_function": "row-marker-wrong-function",
    "omission_bad_path": "omission-path-unresolvable",
    "omission_no_owner": "omission-no-owner",
    "assumption_many_to_many_drift": "assumption-invariants-drift",
    "ghost_orphan_module": "row-path-unresolvable",
    "cfg_disabled_module": "row-path-unresolvable",
    "coordinated_invariant_deletion": "universe-invariant-drift",
    "delete_all_omissions": "universe-omission-drift",
}


def mutate(root, case):
    src = root / "crates/fixture-crate/src/gate.rs"
    mapping = root / "docs/assurance/MAPPING.md"
    assumptions = root / "docs/assurance/assumptions.toml"
    omissions = root / "docs/assurance/omissions.toml"
    if case == "comment_fake_marker":
        src.write_text(src.read_text().replace("// INVARIANT: FIXTURE-ONE\n        if", "/* // INVARIANT: FIXTURE-ONE */\n        if"))
    elif case == "string_fake_marker":
        src.write_text(src.read_text().replace("// INVARIANT: FIXTURE-ONE\n        if", 'let _ = "// INVARIANT: FIXTURE-ONE";\n        if'))
    elif case in {"comment_fake_function", "string_fake_function"}:
        mapping.write_text(mapping.read_text().replace("Gate::evaluate", "Gate::ghost"))
        fake = "// pub fn ghost(&self) {}" if case.startswith("comment") else 'const _: &str = "pub fn ghost(&self) {}";'
        src.write_text(src.read_text().replace("pub fn evaluate", fake + "\n    pub fn evaluate"))
    elif case == "marker_not_adjacent":
        src.write_text(src.read_text().replace("// INVARIANT: FIXTURE-ONE\n        if", "// INVARIANT: FIXTURE-ONE\n        let x = 1;\n        if"))
    elif case == "marker_wrong_function":
        src.write_text(src.read_text().replace("// INVARIANT: FIXTURE-ONE\n        if dangerous()", "if dangerous()").replace("pub fn omitted() {", "pub fn omitted() { // INVARIANT: FIXTURE-ONE\n if dangerous() {} }\npub fn displaced() {"))
    elif case == "omission_bad_path": omissions.write_text(omissions.read_text().replace("::omitted", "::ghost"))
    elif case == "omission_no_owner": omissions.write_text(omissions.read_text().replace('owner="x"', 'owner=""'))
    elif case == "assumption_many_to_many_drift": assumptions.write_text(assumptions.read_text().replace('invariants=["FIXTURE-ONE"]', 'invariants=[]', 1))
    elif case == "ghost_orphan_module":
        mapping.write_text(mapping.read_text().replace("gate::Gate::evaluate", "ghost::ghost"))
        (root / "crates/fixture-crate/src/ghost.rs").write_text("pub fn ghost() {}\n")
    elif case == "cfg_disabled_module":
        mapping.write_text(mapping.read_text().replace("gate::Gate::evaluate", "ghost::ghost"))
        (root / "crates/fixture-crate/src/lib.rs").write_text("#[cfg(any())]\npub mod ghost;\npub mod gate;\n")
        (root / "crates/fixture-crate/src/ghost.rs").write_text("pub fn ghost() {}\n")
    elif case == "coordinated_invariant_deletion":
        mapping.write_text(mapping.read_text().replace(MAPPING.splitlines()[-1] + "\n", ""))
        src.write_text(src.read_text().replace("// INVARIANT: FIXTURE-ONE\n", ""))
        assumptions.write_text(assumptions.read_text().replace('invariants=["FIXTURE-ONE"]', 'invariants=[]'))
    elif case == "delete_all_omissions": omissions.write_text("schema_version=1\n")


def self_test():
    ok = True
    with tempfile.TemporaryDirectory() as raw:
        base = pathlib.Path(raw)
        clean = fixture(base / "clean")
        report = run_checks(clean, 1, 1, 2)
        if report.violations:
            ok = False; print(f"mapping self-test clean failed: {report.violations}", file=sys.stderr)
        for case, expected in CASES.items():
            root = fixture(base / case); mutate(root, case)
            codes = run_checks(root, 1, 1, 2).codes()
            if expected not in codes:
                ok = False; print(f"mapping self-test {case}: expected {expected}, got {sorted(codes)}", file=sys.stderr)
    return ok


if not self_test(): raise SystemExit("check-mapping self-test failed")
report = run_checks(REPO_ROOT)
if report.violations:
    print(f"check-mapping: {len(report.violations)} violation(s)", file=sys.stderr)
    for code, message in report.violations: print(f"  [{code}] {message}", file=sys.stderr)
    raise SystemExit(1)
rows = parse_rows(REPO_ROOT, Report())
assumptions = load_toml(REPO_ROOT, ASSUMPTIONS_REL, "assumption", Report())
omissions = load_toml(REPO_ROOT, OMISSIONS_REL, "omission", Report())
print(f"check-mapping OK: {len(rows)} rows, {len(assumptions)} assumptions, {len(omissions)} enforced omissions; {len(CASES)+1} self-tests passed (1 clean control, {len(CASES)} adversarial)")
PY
