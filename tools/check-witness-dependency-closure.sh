#!/usr/bin/env bash
# Enforce the exact Phase 285 witness-transport package boundary.
set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"

usage() {
  echo "usage: $0 --library-only|--current-targets|--all-targets|--self-test [case]" >&2
  exit 2
}

case "${1:-}" in
  --library-only|--current-targets|--all-targets)
    [ "$#" -eq 1 ] || usage
    ;;
  --self-test)
    [ "$#" -le 2 ] || usage
    ;;
  *) usage ;;
esac

python3 -I - "$ROOT_DIR" "$@" <<'PY'
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import tomllib

ROOT = pathlib.Path(sys.argv[1]).resolve()
MODE = sys.argv[2]
CASE = sys.argv[3] if len(sys.argv) == 4 else None
PACKAGE = "swarm-governance-witness"
LIBRARY = "swarm_governance_witness"
NORMAL = {
    "async-nats", "async-trait", "futures-util", "hex", "serde", "serde_json",
    "rustix", "sha2", "swarm-crypto", "swarm-governance", "thiserror", "tokio",
    "tracing", "zeroize",
}
DEV = {"tokio"}
BUILD = set()
ALLOWED_INTERNAL = {
    "swarm-governance-witness", "swarm-governance", "swarm-consensus",
    "swarm-core", "swarm-crypto", "swarm-policy",
}
FORBIDDEN_INTERNAL = {
    "swarm-whisker", "swarm-ingest-tetragon", "swarm-ingest-json",
    "swarm-ingest-taxii", "swarm-ingest-sentinel", "swarm-pheromone",
    "swarm-response", "swarm-runtime", "swarm-agents", "swarm-runtime-http",
    "swarm-ingest-runtime", "swarm-runtime-workbench", "swarm-evolution",
    "swarm-cli", "swarm-spine", "swarm-guard",
}
EXPECTED_BIN_PATHS = {
    "swarm-governance-witness": "src/bin/swarm-governance-witness.rs",
    "swarm-governance-witness-store": "src/bin/swarm-governance-witness-store.rs",
    "swarm-governance-witness-init": "src/bin/swarm-governance-witness-init.rs",
}
CURRENT_BIN_PATHS = {
    name: path for name, path in EXPECTED_BIN_PATHS.items()
    if name != "swarm-governance-witness-init"
}
CASES = (
    "missing-library-target",
    "forbidden-declared-normal",
    "forbidden-declared-dev",
    "forbidden-declared-build",
    "forbidden-resolved-normal",
    "forbidden-resolved-foreign",
    "forbidden-resolved-dev",
    "forbidden-resolved-build",
    "missing-normal-signer-edge",
    "signer-remains-dev-only",
    "partial-cargo-tree-omission",
    "host-tree-mismatch",
    "all-target-subset-omission",
    "metadata-harness-boundary",
    "self-test-parent-boundary",
    "reverse-governance-edge",
    "wrong-library-name",
    "missing-current-target",
    "extra-current-target",
    "substituted-current-target",
    "same-name-internal-substitution",
    "syntax-invalid-binary-target",
    "type-invalid-binary-target",
)
EXPECTED_DIAGNOSTIC = {
    "missing-library-target": "missing library target source",
    "forbidden-declared-normal": "violation=declared-normal",
    "forbidden-declared-dev": "violation=declared-dev",
    "forbidden-declared-build": "violation=declared-build",
    "forbidden-resolved-normal": "violation=resolved-normal",
    "forbidden-resolved-foreign": "violation=resolved-normal-all-target",
    "forbidden-resolved-dev": "violation=resolved-dev",
    "forbidden-resolved-build": "violation=resolved-build",
    "missing-normal-signer-edge": "violation=declared-normal",
    "signer-remains-dev-only": "violation=declared-dev",
    "partial-cargo-tree-omission": "cargo-tree-normal",
    "host-tree-mismatch": "cargo-tree-normal",
    "all-target-subset-omission": "cargo-tree-normal-target-subset",
    "metadata-harness-boundary": "metadata harness parent refusal before create",
    "self-test-parent-boundary": "self-test scratch parent refusal before create",
    "reverse-governance-edge": "reverse governance dependency",
    "wrong-library-name": "library targets mismatch",
    "missing-current-target": "explicit binary declarations mismatch",
    "extra-current-target": "binary targets mismatch",
    "substituted-current-target": "explicit binary declaration path mismatch: name=swarm-governance-witness-substitute expected=None actual=src/bin/swarm-governance-witness-store.rs",
    "same-name-internal-substitution": "must resolve exactly once",
    "syntax-invalid-binary-target": "target check failed bin swarm-governance-witness-store",
    "type-invalid-binary-target": "target check failed bin swarm-governance-witness-store",
}
STRUCTURED_VIOLATION_CASES = {
    "forbidden-declared-normal",
    "forbidden-declared-dev",
    "forbidden-declared-build",
    "forbidden-resolved-normal",
    "forbidden-resolved-foreign",
    "forbidden-resolved-dev",
    "forbidden-resolved-build",
    "missing-normal-signer-edge",
    "signer-remains-dev-only",
    "partial-cargo-tree-omission",
    "host-tree-mismatch",
    "all-target-subset-omission",
}


class ClosureFailure(Exception):
    pass


def fail(message):
    raise ClosureFailure(message)


def run(root, *args):
    return subprocess.run(
        args,
        cwd=root,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env={**os.environ, "CARGO_TERM_COLOR": "never"},
    )


def command(root, *args):
    result = run(root, *args)
    if result.returncode != 0:
        fail(f"command failed ({' '.join(args)}): {result.stderr.strip()}")
    return result.stdout


def load_toml(path):
    try:
        with path.open("rb") as handle:
            return tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError) as error:
        fail(f"cannot parse {path}: {error}")


def dependency_names(table):
    names = set()
    for section in ("dependencies", "dev-dependencies", "build-dependencies"):
        for name, specification in table.get(section, {}).items():
            names.add(
                specification.get("package", name)
                if isinstance(specification, dict)
                else name
            )
    for target in table.get("target", {}).values():
        if not isinstance(target, dict):
            continue
        for section in ("dependencies", "dev-dependencies", "build-dependencies"):
            for name, specification in target.get(section, {}).items():
                names.add(
                    specification.get("package", name)
                    if isinstance(specification, dict)
                    else name
                )
    return names


def metadata(root, filter_platform=None):
    arguments = [
        "cargo", "metadata", "--format-version", "1", "--locked", "--offline",
        "--all-features",
    ]
    if filter_platform is not None:
        arguments.extend(("--filter-platform", filter_platform))
    output = command(root, *arguments)
    try:
        return json.loads(output)
    except json.JSONDecodeError as error:
        fail(f"cargo metadata returned invalid JSON: {error}")


def canonical(path):
    try:
        return pathlib.Path(path).resolve(strict=True)
    except OSError as error:
        fail(f"cannot canonicalize {path}: {error}")


def expected_internal_manifest(root, name):
    return canonical(root / "crates" / name / "Cargo.toml")


def validate_internal_identities(root, data):
    packages = data.get("packages", [])
    identifiers = [package["id"] for package in packages]
    if len(identifiers) != len(set(identifiers)):
        fail("cargo metadata contains duplicate package IDs")
    workspace_members = data.get("workspace_members", [])
    if len(workspace_members) != len(set(workspace_members)):
        fail("cargo metadata contains duplicate workspace member IDs")
    package_by_id = {package["id"]: package for package in packages}
    if any(identifier not in package_by_id for identifier in workspace_members):
        fail("workspace member ID is absent from metadata packages")

    allowed_ids = {}
    for name in sorted(ALLOWED_INTERNAL):
        matches = [package for package in packages if package["name"] == name]
        if len(matches) != 1:
            fail(f"allowed internal name {name} must resolve exactly once; observed={len(matches)}")
        package = matches[0]
        if workspace_members.count(package["id"]) != 1:
            fail(f"allowed internal ID is not one exact workspace member: {name}")
        if package.get("source") is not None:
            fail(f"allowed internal package has foreign source: {name}")
        expected_manifest = expected_internal_manifest(root, name)
        if canonical(package["manifest_path"]) != expected_manifest:
            fail(
                f"allowed internal manifest path mismatch: {name} "
                f"expected={expected_manifest} actual={package['manifest_path']}"
            )
        allowed_ids[name] = package["id"]
    if len(set(allowed_ids.values())) != len(ALLOWED_INTERNAL):
        fail("allowed internal package IDs are not unique")
    return package_by_id, set(workspace_members), allowed_ids


def dependency_kind(dependency_kind_value):
    return dependency_kind_value.get("kind") or "normal"


def normalized_dependency_name(name):
    return name.replace("-", "_")


def activated_optional_dependencies(package, node):
    feature_table = package.get("features", {})
    pending = list(node.get("features", []))
    visited = set()
    activated = set()
    while pending:
        feature = pending.pop()
        if feature in visited:
            continue
        visited.add(feature)
        for item in feature_table.get(feature, []):
            if item.startswith("dep:"):
                activated.add(normalized_dependency_name(item[4:]))
                continue
            if "/" in item:
                dependency_name = item.split("/", 1)[0]
                conditional = dependency_name.endswith("?")
                dependency_name = dependency_name.removesuffix("?")
                if not conditional:
                    activated.add(normalized_dependency_name(dependency_name))
                continue
            if item in feature_table:
                pending.append(item)
            else:
                activated.add(normalized_dependency_name(item))
    return activated


def dependency_resolve_name(entry, target_package):
    if entry.get("rename") is not None:
        return normalized_dependency_name(entry["rename"])
    library_targets = [
        target
        for target in target_package.get("targets", [])
        if set(target.get("kind", [])) & {"lib", "proc-macro"}
    ]
    if len(library_targets) == 1:
        return normalized_dependency_name(library_targets[0]["name"])
    return normalized_dependency_name(target_package["name"])


def active_dependency_kinds(packages, package, node, dependency):
    local_name = normalized_dependency_name(dependency["name"])
    activated_optional = activated_optional_dependencies(package, node)
    target_package = packages.get(dependency["pkg"])
    if target_package is None:
        fail(f"resolve edge references missing target package {dependency['pkg']}")
    active = set()
    for value in dependency.get("dep_kinds", []):
        kind = dependency_kind(value)
        manifest_entries = [
            entry
            for entry in package.get("dependencies", [])
            if normalized_dependency_name(entry["name"])
            == normalized_dependency_name(target_package["name"])
            and dependency_resolve_name(entry, target_package) == local_name
            and (entry.get("kind") or "normal") == kind
        ]
        if not manifest_entries:
            fail(
                "metadata resolve edge lacks matching manifest dependency: "
                f"package={package['id']} dependency={dependency['name']} kind={kind}"
            )
        if any(not entry.get("optional") for entry in manifest_entries):
            active.add(kind)
        elif any(
            normalized_dependency_name(entry.get("rename") or entry["name"])
            in activated_optional
            for entry in manifest_entries
        ):
            active.add(kind)
    return active


def resolved_closure(data, root_id, root_kinds, transitive_kinds):
    resolve = data.get("resolve")
    if not resolve or not resolve.get("nodes"):
        fail("cargo metadata resolve graph is empty")
    nodes = {node["id"]: node for node in resolve["nodes"]}
    packages = {package["id"]: package for package in data.get("packages", [])}
    if root_id not in nodes:
        fail(f"resolve graph omitted root package ID {root_id}")
    observed = {root_id}
    pending = [root_id]
    while pending:
        identifier = pending.pop()
        node = nodes.get(identifier)
        if node is None:
            fail(f"resolve graph references missing node {identifier}")
        package = packages.get(identifier)
        if package is None:
            fail(f"resolve graph references missing package {identifier}")
        for dependency in node.get("deps", []):
            dependency_kinds = active_dependency_kinds(
                packages,
                package,
                node,
                dependency,
            )
            permitted_kinds = root_kinds if identifier == root_id else transitive_kinds
            if dependency_kinds.isdisjoint(permitted_kinds):
                continue
            target_id = dependency["pkg"]
            if target_id not in observed:
                observed.add(target_id)
                pending.append(target_id)
    return observed


def rustc_host(root):
    rustc_version = command(root, "rustc", "-vV")
    host_matches = re.findall(r"^host: (\S+)$", rustc_version, re.MULTILINE)
    if len(host_matches) != 1:
        fail("rustc host triple is missing or ambiguous")
    return host_matches[0]


def cargo_tree_output(root, package_spec, edges, target, all_features=True):
    arguments = [
        "cargo", "tree", "-p", package_spec, "--locked", "--offline",
        "--target", target,
    ]
    if all_features:
        arguments.append("--all-features")
    arguments.extend(
        ("--edges", edges, "--prefix", "none", "--no-dedupe", "--format", "{p}")
    )
    return command(root, *arguments)


def parse_cargo_tree_package_ids(root, data, output):
    rows = [line.strip() for line in output.splitlines() if line.strip()]
    if not rows:
        fail("cargo tree returned zero rows")

    packages = data.get("packages", [])
    observed = set()
    for row in rows:
        if row.endswith(" (proc-macro)"):
            row = row[: -len(" (proc-macro)")]
        match = re.fullmatch(r"([^ ]+) v([^ ]+)(?: \((.*)\))?", row)
        if match is None:
            fail(f"cargo-tree row has unknown format: {row!r}")
        name, version, locator = match.groups()
        candidates = [
            package
            for package in packages
            if package["name"] == name and package["version"] == version
        ]
        if locator is not None:
            path_matches = []
            locator_path = pathlib.Path(locator)
            if locator_path.is_absolute():
                path_matches = [
                    package
                    for package in candidates
                    if package.get("source") is None
                    and canonical(package["manifest_path"]).parent == canonical(locator_path)
                ]
            source_matches = [
                package
                for package in candidates
                if package.get("source") is not None
                and (
                    locator == package["source"]
                    or locator in package["source"]
                    or package["source"] in locator
                )
            ]
            candidates = path_matches + source_matches
        if len(candidates) != 1:
            fail(
                "cargo-tree row does not map to one exact metadata package ID: "
                f"row={row!r} matches={len(candidates)}"
            )
        observed.add(candidates[0]["id"])
    return observed


def cargo_tree_package_ids(
    root,
    data,
    package_spec,
    edges,
    target,
    output_override=None,
    all_features=True,
):
    output = (
        output_override
        if output_override is not None
        else cargo_tree_output(root, package_spec, edges, target, all_features)
    )
    return parse_cargo_tree_package_ids(root, data, output)


def strict_partial_cargo_tree_output(root, data, root_id, target):
    output = cargo_tree_output(root, PACKAGE, "normal", target)
    unique_rows = list(
        dict.fromkeys(line.strip() for line in output.splitlines() if line.strip())
    )
    rows_with_ids = []
    for row in unique_rows:
        identifiers = parse_cargo_tree_package_ids(root, data, row)
        if len(identifiers) != 1:
            fail(f"one cargo-tree row mapped to {len(identifiers)} package IDs")
        rows_with_ids.append((row, next(iter(identifiers))))
    full_ids = {identifier for _, identifier in rows_with_ids}
    non_root = sorted(full_ids - {root_id})
    if root_id not in full_ids or len(non_root) < 2:
        fail("cannot construct strict nontrivial cargo-tree subset")
    selected = {root_id, *non_root[: max(1, len(non_root) // 2)]}
    if not 1 < len(selected) < len(full_ids):
        fail("partial cargo-tree control is not a strict nontrivial subset")
    partial_rows = [row for row, identifier in rows_with_ids if identifier in selected]
    partial_output = "\n".join(partial_rows) + "\n"
    if parse_cargo_tree_package_ids(root, data, partial_output) != selected:
        fail("partial cargo-tree parser did not preserve the selected exact IDs")
    return partial_output


def package_scoped_metadata(root, subject_data, package_id):
    subject_packages = {package["id"]: package for package in subject_data["packages"]}
    subject = subject_packages.get(package_id)
    if subject is None:
        fail(f"cannot scope metadata to unknown package ID {package_id}")
    features = sorted(subject.get("features", {}))
    temporary_parent = validated_temp_parent("metadata harness", root)
    temporary = tempfile.TemporaryDirectory(
        prefix="phase285-metadata-scope.",
        dir=temporary_parent,
    )
    harness = pathlib.Path(temporary.name).resolve()
    try:
        for boundary in git_boundary_paths():
            if within(harness, boundary) or within(boundary, harness):
                if any(harness.iterdir()):
                    fail("metadata harness boundary check followed a harness write")
                fail(
                    "metadata harness boundary refusal before write: "
                    f"git_boundary={boundary}"
                )
        if within(harness, ROOT) or within(harness, root):
            if any(harness.iterdir()):
                fail("metadata harness subject check followed a harness write")
            fail(
                "metadata harness boundary refusal before write: "
                f"subject_root={root}"
            )
        (harness / "src").mkdir()
        (harness / "src/lib.rs").write_text("", encoding="utf-8")
        dependency_path = canonical(subject["manifest_path"]).parent
        (harness / "Cargo.toml").write_text(
            '[package]\nname = "phase285-metadata-scope"\nversion = "0.0.0"\n'
            'edition = "2024"\n\n[dependencies.subject]\n'
            f'package = {json.dumps(subject["name"])}\n'
            f'path = {json.dumps(str(dependency_path))}\n'
            'default-features = false\n'
            f'features = {json.dumps(features)}\n\n[workspace]\n',
            encoding="utf-8",
        )
        shutil.copy2(root / "Cargo.lock", harness / "Cargo.lock")
        host = rustc_host(root)
        command(
            harness, "cargo", "metadata", "--format-version", "1", "--offline",
            "--filter-platform", host,
        )
        scoped = metadata(harness, host)
        harness_manifest = canonical(harness / "Cargo.toml")
        for package in scoped.get("packages", []):
            if canonical(package["manifest_path"]) == harness_manifest:
                continue
            locked = subject_packages.get(package["id"])
            if locked is None:
                fail(
                    "package-scoped metadata escaped the subject locked graph: "
                    f"{package['id']}"
                )
            for field in ("name", "version", "source", "checksum"):
                if package.get(field) != locked.get(field):
                    fail(
                        "package-scoped metadata identity mismatch: "
                        f"id={package['id']} field={field}"
                    )
        if package_id not in {package["id"] for package in scoped["packages"]}:
            fail(f"package-scoped metadata omitted subject package {package_id}")
        return scoped
    finally:
        temporary.cleanup()
        if harness.exists():
            fail(f"package-scoped metadata cleanup failed: {harness}")


def direct_dependency_ids(data, root_id, kind):
    resolve = data.get("resolve")
    if not resolve or not resolve.get("nodes"):
        fail("cargo metadata resolve graph is empty")
    nodes = {node["id"]: node for node in resolve["nodes"]}
    node = nodes.get(root_id)
    if node is None:
        fail(f"resolve graph omitted root package ID {root_id}")
    identifiers = set()
    for dependency in node.get("deps", []):
        kinds = {dependency_kind(value) for value in dependency.get("dep_kinds", [])}
        if not kinds:
            kinds = {"normal"}
        if kind in kinds:
            identifiers.add(dependency["pkg"])
    return identifiers


def check_target(root, target_kind, target_name):
    selector = "--lib" if target_kind == "lib" else "--bin"
    args = ["cargo", "check", "-p", PACKAGE, selector]
    if target_kind == "bin":
        args.append(target_name)
    args.extend(["--locked", "--offline"])
    result = run(root, *args)
    if result.returncode != 0:
        fail(
            f"target check failed {target_kind} {target_name}: "
            f"{result.stderr.strip()}"
        )


def evaluate(root, target_mode="library-only", tree_output_overrides=None):
    if target_mode is False:
        target_mode = "library-only"
    elif target_mode is True:
        target_mode = "all-targets"
    if target_mode not in {"library-only", "current-targets", "all-targets"}:
        fail(f"unknown target mode {target_mode}")
    root = canonical(root)
    validated_temp_parent("evaluation scratch", root)
    tree_output_overrides = tree_output_overrides or {}
    root_manifest = load_toml(root / "Cargo.toml")
    members = set(root_manifest.get("workspace", {}).get("members", []))
    expected_member = "crates/swarm-governance-witness"
    if expected_member not in members:
        fail(f"missing workspace member {expected_member}")
    witness_manifest_path = root / expected_member / "Cargo.toml"
    witness_manifest = load_toml(witness_manifest_path)
    if witness_manifest.get("package", {}).get("name") != PACKAGE:
        fail(f"missing package {PACKAGE}")
    governance_manifest = load_toml(root / "crates/swarm-governance/Cargo.toml")
    if PACKAGE in dependency_names(governance_manifest):
        fail("reverse governance dependency on witness transport")

    data = metadata(root)
    package_by_id, workspace_ids, allowed_ids = validate_internal_identities(root, data)
    witness = package_by_id[allowed_ids[PACKAGE]]

    violations = []

    def record_violation(code, detail):
        violations.append((code, detail))

    declared = {"normal": [], "dev": [], "build": []}
    for dependency in witness.get("dependencies", []):
        kind = dependency.get("kind") or "normal"
        if kind not in declared:
            fail(f"unknown dependency kind {kind}")
        if (
            dependency.get("rename") is not None
            or dependency.get("optional")
            or dependency.get("target") is not None
        ):
            fail(f"dependency must be unconditional and unrenamed: {dependency['name']}")
        declared[kind].append(dependency["name"])
    for kind, expected in (("normal", NORMAL), ("dev", DEV), ("build", BUILD)):
        actual = set(declared[kind])
        if len(declared[kind]) != len(actual):
            record_violation(f"declared-{kind}", "duplicate dependency")
        if actual != expected:
            record_violation(
                f"declared-{kind}",
                f"mismatch: missing={sorted(expected - actual)} "
                f"extra={sorted(actual - expected)}"
            )
        forbidden = actual & FORBIDDEN_INTERNAL
        if forbidden:
            record_violation(
                f"declared-{kind}",
                f"forbidden={sorted(forbidden)}",
            )

    for dependency in witness.get("dependencies", []):
        name = dependency["name"]
        if name not in ALLOWED_INTERNAL:
            continue
        expected_path = expected_internal_manifest(root, name).parent
        dependency_path = dependency.get("path")
        if dependency_path is None or canonical(dependency_path) != expected_path:
            fail(f"internal dependency path mismatch: {name}")

    library_targets = []
    binary_targets = []
    for target in witness.get("targets", []):
        kinds = set(target.get("kind", []))
        if "lib" in kinds:
            library_targets.append(target)
        if "bin" in kinds:
            binary_targets.append(target)
    library_names = {target["name"] for target in library_targets}
    if len(library_targets) != 1 or library_names != {LIBRARY}:
        fail(f"library targets mismatch: {sorted(library_names)}")
    library_source = root / expected_member / "src/lib.rs"
    if not library_source.is_file():
        fail("missing library target source")
    expected_library_path = canonical(library_source)
    if canonical(library_targets[0]["src_path"]) != expected_library_path:
        fail("library source path mismatch")

    binary_names = {target["name"] for target in binary_targets}
    explicit_bins = witness_manifest.get("bin", [])
    if not isinstance(explicit_bins, list) or any(
        not isinstance(entry, dict) for entry in explicit_bins
    ):
        fail("explicit binary declarations are malformed")
    explicit_names = [entry.get("name") for entry in explicit_bins]
    if (
        any(set(entry) != {"name", "path"} for entry in explicit_bins)
        or any(not isinstance(name, str) for name in explicit_names)
        or len(explicit_names) != len(set(explicit_names))
        or set(explicit_names) != binary_names
    ):
        fail(
            "explicit binary declarations mismatch: "
            f"expected={sorted(binary_names)} actual={sorted(str(name) for name in explicit_names)}"
        )
    for entry in explicit_bins:
        name = entry["name"]
        expected_path = EXPECTED_BIN_PATHS.get(name)
        if expected_path is None or entry["path"] != expected_path:
            fail(
                "explicit binary declaration path mismatch: "
                f"name={name} expected={expected_path} actual={entry['path']}"
            )
    expected_bins = (
        set(CURRENT_BIN_PATHS)
        if target_mode == "current-targets"
        else set(EXPECTED_BIN_PATHS)
        if target_mode == "all-targets"
        else binary_names
    )
    if len(binary_targets) != len(binary_names) or binary_names != expected_bins:
        missing_bins = expected_bins - binary_names
        extra_bins = binary_names - expected_bins
        if (
            target_mode == "all-targets"
            and missing_bins == {"swarm-governance-witness-init"}
            and not extra_bins
            and len(binary_targets) == len(binary_names)
        ):
            fail(
                "missing explicit witness target: swarm-governance-witness-init "
                "(expected at src/bin/swarm-governance-witness-init.rs)"
            )
        fail(
            f"binary targets mismatch: expected={sorted(expected_bins)} "
            f"actual={sorted(binary_names)}"
        )
    if target_mode != "library-only":
        for target in binary_targets:
            expected_path = canonical(
                root / expected_member / EXPECTED_BIN_PATHS[target["name"]]
            )
            if canonical(target["src_path"]) != expected_path:
                fail(f"binary source path mismatch: {target['name']}")

    host = rustc_host(root)
    tree_closures = {
        "normal": cargo_tree_package_ids(
            root,
            data,
            PACKAGE,
            "normal",
            host,
            tree_output_overrides.get("normal"),
        ),
        "dev": cargo_tree_package_ids(root, data, PACKAGE, "normal,dev", host),
        "build": cargo_tree_package_ids(root, data, PACKAGE, "normal,build", host),
    }
    all_target_tree_closures = {
        "normal": cargo_tree_package_ids(
            root,
            data,
            PACKAGE,
            "normal",
            "all",
            tree_output_overrides.get("normal-all"),
        ),
        "dev": cargo_tree_package_ids(root, data, PACKAGE, "normal,dev", "all"),
        "build": cargo_tree_package_ids(root, data, PACKAGE, "normal,build", "all"),
    }
    scoped_witness = package_scoped_metadata(root, data, allowed_ids[PACKAGE])
    closures = {
        "normal": resolved_closure(
            scoped_witness,
            allowed_ids[PACKAGE],
            {"normal"},
            {"normal"},
        ),
        "build": resolved_closure(
            scoped_witness,
            allowed_ids[PACKAGE],
            {"normal", "build"},
            {"normal", "build"},
        ),
    }
    direct_normal_ids = direct_dependency_ids(data, allowed_ids[PACKAGE], "normal")
    direct_dev_ids = direct_dependency_ids(data, allowed_ids[PACKAGE], "dev")
    expected_dev_ids = {
        identifier
        for identifier in direct_normal_ids
        if package_by_id[identifier]["name"] in DEV
    }
    if direct_dev_ids != expected_dev_ids:
        record_violation(
            "declared-dev",
            "direct dependencies must reuse governed normal IDs: "
            f"expected={sorted(expected_dev_ids)} actual={sorted(direct_dev_ids)}",
        )
    metadata_dev_root_ids = {allowed_ids[PACKAGE]}
    tree_dev_root_ids = {allowed_ids[PACKAGE]}
    for identifier in sorted(expected_dev_ids):
        package = package_by_id.get(identifier)
        if package is None:
            fail(f"direct dev dependency references unknown package ID {identifier}")
        metadata_dev_root_ids.update(
            resolved_closure(scoped_witness, identifier, {"normal"}, {"normal"})
        )
        package_spec = f"{package['name']}@{package['version']}"
        tree_dev_root_ids.update(
            cargo_tree_package_ids(
                root, data, package_spec, "normal", host, all_features=False
            )
        )
    closures["dev-root"] = metadata_dev_root_ids
    closures["dev"] = closures["normal"] | metadata_dev_root_ids
    tree_closures["dev-root"] = tree_dev_root_ids

    for kind in ("normal", "dev", "build", "dev-root"):
        metadata_ids = closures[kind]
        tree_ids = tree_closures[kind]
        minimum = 1 if kind == "dev-root" else 2
        if metadata_ids != tree_ids or len(metadata_ids) < minimum or len(tree_ids) < minimum:
            record_violation(
                f"cargo-tree-{kind}",
                f"metadata/tree ID mismatch: metadata={len(metadata_ids)} "
                f"tree={len(tree_ids)} "
                f"missing={sorted(metadata_ids - tree_ids)} "
                f"extra={sorted(tree_ids - metadata_ids)}",
            )

    for kind in ("normal", "dev", "build"):
        host_ids = tree_closures[kind]
        all_ids = all_target_tree_closures[kind]
        if not host_ids <= all_ids:
            record_violation(
                f"cargo-tree-{kind}-target-subset",
                f"host-only={sorted(host_ids - all_ids)}",
            )
        for identifier in all_ids:
            package = package_by_id.get(identifier)
            if package is None:
                record_violation(
                    f"cargo-tree-{kind}-all-target-identity",
                    f"unknown locked package ID={identifier}",
                )
                continue
            name = package["name"]
            if name in FORBIDDEN_INTERNAL:
                record_violation(
                    f"resolved-{kind}-all-target",
                    f"forbidden={name} ({identifier})",
                )
            if identifier in workspace_ids or name.startswith("swarm-"):
                expected_id = allowed_ids.get(name)
                if expected_id != identifier:
                    record_violation(
                        f"resolved-{kind}-all-target",
                        f"unexpected internal={name} ({identifier})",
                    )

    for kind, identifiers in closures.items():
        observed_internal = set()
        for identifier in identifiers:
            package = package_by_id.get(identifier)
            if package is None:
                fail(f"resolved {kind} closure contains unknown package ID {identifier}")
            name = package["name"]
            if name in FORBIDDEN_INTERNAL:
                record_violation(
                    f"resolved-{kind}",
                    f"forbidden={name} ({identifier})",
                )
                continue
            if identifier in workspace_ids or name.startswith("swarm-"):
                expected_id = allowed_ids.get(name)
                if expected_id != identifier:
                    record_violation(
                        f"resolved-{kind}",
                        f"unexpected internal={name} ({identifier})",
                    )
                    continue
                observed_internal.add(identifier)
        expected_internal_ids = (
            {allowed_ids[PACKAGE]} if kind == "dev-root" else set(allowed_ids.values())
        )
        if observed_internal != expected_internal_ids:
            missing = sorted(expected_internal_ids - observed_internal)
            extra = sorted(observed_internal - expected_internal_ids)
            record_violation(
                f"resolved-{kind}",
                f"internal ID mismatch: missing={missing} extra={extra}",
            )

    if violations:
        fail(
            "; ".join(
                f"violation={code} detail={detail}" for code, detail in violations
            )
        )

    checked_targets = 0
    if target_mode != "library-only":
        check_target(root, "lib", LIBRARY)
        checked_targets += 1
        for name in sorted(expected_bins):
            check_target(root, "bin", name)
            checked_targets += 1
    print(
        "witness_dependency_closure "
        f"mode={target_mode} "
        f"libraries={len(library_targets)} binaries={len(binary_targets)} "
        f"declared_normal={len(set(declared['normal']))} "
        f"declared_dev={len(set(declared['dev']))} "
        f"declared_build={len(set(declared['build']))} "
        f"resolved_normal={len(closures['normal'])} resolved_dev={len(closures['dev'])} "
        f"resolved_build={len(closures['build'])} "
        f"resolved_dev_root={len(closures['dev-root'])} internal_ids={len(allowed_ids)} "
        f"cargo_tree_id_checks=7 checked_targets={checked_targets} forbidden=0"
    )
    return data


def within(path, parent):
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def validated_temp_parent(purpose, *subject_roots):
    configured = os.environ.get("TMPDIR")
    requested = pathlib.Path(configured) if configured else pathlib.Path(tempfile.gettempdir())
    try:
        parent = requested.resolve(strict=True)
    except OSError as error:
        fail(f"{purpose} parent is unavailable before create: {error}")
    if not parent.is_dir():
        fail(f"{purpose} parent is not a directory before create: {parent}")
    boundaries = {ROOT, *map(canonical, subject_roots), *git_boundary_paths()}
    for boundary in boundaries:
        if parent == boundary or within(parent, boundary):
            fail(
                f"{purpose} parent refusal before create: "
                f"parent={parent} boundary={boundary}"
            )
    return parent


def git_boundary_paths():
    paths = {ROOT}
    for flag in ("--git-dir", "--git-common-dir"):
        output = command(ROOT, "git", "rev-parse", "--path-format=absolute", flag).strip()
        paths.add(pathlib.Path(output).resolve())
    return paths


def copy_exact(source, destination, identities):
    source = pathlib.Path(source)
    destination = pathlib.Path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    if source.is_symlink():
        destination.symlink_to(os.readlink(source))
    else:
        shutil.copy2(source, destination)
    identities[destination] = source


EXCLUDED_PROJECTION_DIRECTORIES = {".git", "target", "__pycache__"}


def enumerate_regular_entries(root, relative_roots):
    inventory = {}
    for relative_root in sorted(set(relative_roots)):
        source = root / relative_root
        if not source.exists() and not source.is_symlink():
            continue
        if source.is_file() or source.is_symlink():
            inventory[relative_root] = source
            continue
        for current, directories, files in os.walk(source, followlinks=False):
            current_path = pathlib.Path(current)
            directories[:] = sorted(
                directory
                for directory in directories
                if directory not in EXCLUDED_PROJECTION_DIRECTORIES
            )
            for directory in list(directories):
                entry = current_path / directory
                if entry.is_symlink():
                    inventory[entry.relative_to(root)] = entry
                    directories.remove(directory)
            for filename in sorted(files):
                entry = current_path / filename
                inventory[entry.relative_to(root)] = entry
    return inventory


def assert_byte_identities(identities):
    if not identities:
        fail("scratch projection copied zero subject files")
    for copied, subject in identities.items():
        if subject.is_symlink():
            if not copied.is_symlink() or os.readlink(copied) != os.readlink(subject):
                fail(f"scratch symlink identity mismatch: {subject}")
        elif copied.read_bytes() != subject.read_bytes():
            fail(f"scratch byte identity mismatch: {subject}")


def target_signature(package, workspace_root):
    manifest = canonical(package["manifest_path"])
    relative_manifest = manifest.relative_to(workspace_root).as_posix()
    targets = []
    for target in package.get("targets", []):
        relative_source = canonical(target["src_path"]).relative_to(workspace_root).as_posix()
        targets.append(
            (
                target["name"],
                tuple(target.get("kind", [])),
                tuple(target.get("crate_types", [])),
                relative_source,
                target.get("edition"),
                target.get("doc"),
                target.get("doctest"),
                target.get("test"),
            )
        )
    return relative_manifest, tuple(sorted(targets))


def assert_target_projection(subject_data, copied_data, subject_root, copied_root):
    subject_members = {
        package["name"]: target_signature(package, subject_root)
        for package in subject_data["packages"]
        if package["id"] in subject_data["workspace_members"]
    }
    copied_members = {
        package["name"]: target_signature(package, copied_root)
        for package in copied_data["packages"]
        if package["id"] in copied_data["workspace_members"]
    }
    if copied_members != subject_members:
        fail("scratch metadata target paths/config differ from subject")


def build_projection(subject_data, container):
    scratch = container / "subject"
    scratch.mkdir()
    for boundary in git_boundary_paths():
        if within(scratch.resolve(), boundary.resolve()) or within(boundary.resolve(), scratch.resolve()):
            fail(f"scratch projection overlaps repository/git boundary: {boundary}")
    if within(scratch.resolve(), ROOT):
        fail("scratch projection is inside subject root")

    workspace_ids = set(subject_data["workspace_members"])
    package_roots = set()
    for package in subject_data["packages"]:
        if package["id"] not in workspace_ids:
            continue
        manifest = canonical(package["manifest_path"])
        try:
            package_roots.add(manifest.parent.relative_to(ROOT))
        except ValueError:
            fail(f"workspace package root escapes subject root: {manifest.parent}")

    projection_roots = {pathlib.Path("Cargo.toml"), pathlib.Path("Cargo.lock")}
    for name in ("rust-toolchain", "rust-toolchain.toml"):
        if (ROOT / name).exists():
            projection_roots.add(pathlib.Path(name))
    if (ROOT / ".cargo").exists():
        projection_roots.add(pathlib.Path(".cargo"))
    projection_roots.update(package_roots)

    subject_inventory = enumerate_regular_entries(ROOT, projection_roots)
    identities = {}
    for relative, source in sorted(subject_inventory.items()):
        copy_exact(source, scratch / relative, identities)

    copied_inventory = enumerate_regular_entries(scratch, projection_roots)
    if set(copied_inventory) != set(subject_inventory):
        fail(
            "scratch projection inventory mismatch: "
            f"missing={sorted(set(subject_inventory) - set(copied_inventory))} "
            f"extra={sorted(set(copied_inventory) - set(subject_inventory))}"
        )
    for relative, copied in copied_inventory.items():
        source = subject_inventory[relative]
        if source.is_symlink():
            if not copied.is_symlink() or os.readlink(copied) != os.readlink(source):
                fail(f"scratch symlink identity mismatch: {source}")
        elif copied.read_bytes() != source.read_bytes():
            fail(f"scratch byte identity mismatch: {source}")
    assert_byte_identities(identities)
    copied_data = metadata(scratch)
    assert_target_projection(subject_data, copied_data, ROOT, scratch)
    return scratch, identities


def replace_once(path, old, new):
    text = path.read_text(encoding="utf-8")
    if text.count(old) != 1:
        fail(f"mutation precondition mismatch in {path}: {old!r}")
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


def refresh_lock(root):
    command(root, "cargo", "generate-lockfile", "--offline")


def add_future_bins(root):
    manifest = root / "crates" / PACKAGE / "Cargo.toml"
    declarations = []
    for name, relative in EXPECTED_BIN_PATHS.items():
        declarations.append(f'[[bin]]\nname = "{name}"\npath = "{relative}"\n')
        source = root / "crates" / PACKAGE / relative
        source.parent.mkdir(parents=True, exist_ok=True)
        source.write_text("fn main() {}\n", encoding="utf-8")
    with manifest.open("a", encoding="utf-8") as handle:
        handle.write("\n" + "\n".join(declarations))


def mutate(root, container, case):
    witness_manifest = root / "crates" / PACKAGE / "Cargo.toml"
    governance_manifest = root / "crates" / "swarm-governance" / "Cargo.toml"
    crypto_manifest = root / "crates" / "swarm-crypto" / "Cargo.toml"
    if case == "missing-library-target":
        (root / "crates" / PACKAGE / "src/lib.rs").unlink()
    elif case == "forbidden-declared-normal":
        replace_once(
            witness_manifest,
            "[dev-dependencies]",
            "swarm-runtime.workspace = true\n\n[dev-dependencies]",
        )
        refresh_lock(root)
    elif case == "forbidden-declared-dev":
        replace_once(
            witness_manifest,
            "[build-dependencies]",
            "swarm-runtime.workspace = true\n\n[build-dependencies]",
        )
        refresh_lock(root)
    elif case == "forbidden-declared-build":
        replace_once(
            witness_manifest,
            "[build-dependencies]\n\n[lints]",
            "[build-dependencies]\nswarm-runtime.workspace = true\n\n[lints]",
        )
        refresh_lock(root)
    elif case == "forbidden-resolved-normal":
        replace_once(
            governance_manifest,
            "[target.'cfg(unix)'.dependencies]",
            "swarm-whisker.workspace = true\n\n[target.'cfg(unix)'.dependencies]",
        )
        refresh_lock(root)
    elif case == "forbidden-resolved-foreign":
        with governance_manifest.open("a", encoding="utf-8") as handle:
            handle.write(
                "\n[target.'cfg(target_os = \"windows\")'.dependencies]\n"
                "swarm-whisker.workspace = true\n"
            )
        refresh_lock(root)
    elif case == "forbidden-resolved-dev":
        whisker_manifest = root / "crates" / "swarm-whisker" / "Cargo.toml"
        whisker_manifest.write_text(
            '[package]\nname = "swarm-whisker"\nversion.workspace = true\n'
            'edition.workspace = true\nlicense.workspace = true\n\n'
            '[dependencies]\n\n[lints]\nworkspace = true\n',
            encoding="utf-8",
        )
        replace_once(
            crypto_manifest,
            "[lints]",
            "swarm-whisker.workspace = true\n\n[lints]",
        )
        refresh_lock(root)
    elif case == "forbidden-resolved-build":
        with governance_manifest.open("a", encoding="utf-8") as handle:
            handle.write("\n[build-dependencies]\nswarm-whisker.workspace = true\n")
        refresh_lock(root)
    elif case == "missing-normal-signer-edge":
        replace_once(
            witness_manifest,
            "swarm-crypto.workspace = true\n",
            "",
        )
        refresh_lock(root)
    elif case == "signer-remains-dev-only":
        replace_once(
            witness_manifest,
            "swarm-crypto.workspace = true\n",
            "",
        )
        replace_once(
            witness_manifest,
            "[dev-dependencies]\n",
            "[dev-dependencies]\nswarm-crypto.workspace = true\n",
        )
        refresh_lock(root)
    elif case == "reverse-governance-edge":
        replace_once(
            governance_manifest,
            "[target.'cfg(unix)'.dependencies]",
            f"{PACKAGE}.workspace = true\n\n[target.'cfg(unix)'.dependencies]",
        )
    elif case == "wrong-library-name":
        replace_once(
            witness_manifest,
            f'name = "{LIBRARY}"',
            'name = "wrong_witness_library"',
        )
    elif case == "missing-current-target":
        replace_once(
            witness_manifest,
            '[[bin]]\nname = "swarm-governance-witness-store"\npath = "src/bin/swarm-governance-witness-store.rs"\n\n',
            "",
        )
    elif case == "extra-current-target":
        name = "swarm-governance-witness-init"
        relative = EXPECTED_BIN_PATHS[name]
        with witness_manifest.open("a", encoding="utf-8") as handle:
            handle.write(f'\n[[bin]]\nname = "{name}"\npath = "{relative}"\n')
        source = root / "crates" / PACKAGE / relative
        source.write_text("fn main() {}\n", encoding="utf-8")
    elif case == "substituted-current-target":
        replace_once(
            witness_manifest,
            'name = "swarm-governance-witness-store"',
            'name = "swarm-governance-witness-substitute"',
        )
    elif case == "same-name-internal-substitution":
        foreign = container / "foreign-swarm-crypto"
        foreign.mkdir()
        (foreign / "src").mkdir()
        (foreign / "Cargo.toml").write_text(
            '[package]\nname = "swarm-crypto"\nversion = "0.1.1"\nedition = "2024"\n',
            encoding="utf-8",
        )
        (foreign / "src/lib.rs").write_text("#![forbid(unsafe_code)]\n", encoding="utf-8")
        root_manifest = root / "Cargo.toml"
        replace_once(
            root_manifest,
            'swarm-crypto = { version = "0.1.0", path = "crates/swarm-crypto" }',
            'swarm-crypto = { version = "0.1.1", path = "../foreign-swarm-crypto" }',
        )
        refresh_lock(root)
    elif case in {"syntax-invalid-binary-target", "type-invalid-binary-target"}:
        pass
    else:
        fail(f"unknown self-test {case}")


def expect_mutation_failure(
    root,
    case,
    target_mode="library-only",
    tree_output_overrides=None,
):
    try:
        evaluate(root, target_mode, tree_output_overrides)
    except ClosureFailure as error:
        diagnostic = str(error)
        expected = EXPECTED_DIAGNOSTIC[case]
        if case in STRUCTURED_VIOLATION_CASES:
            violation_codes = set(
                re.findall(r"(?:^|; )violation=([^ ]+)", diagnostic)
            )
            matched = expected.removeprefix("violation=") in violation_codes
        else:
            matched = expected in diagnostic
        if not matched:
            fail(
                f"self-test {case} failed for wrong reason: "
                f"expected={expected!r} actual={diagnostic!r}"
            )
        return diagnostic
    fail(f"self-test mutation unexpectedly passed: {case}")


def run_self_test_parent_control():
    before = {entry.name for entry in ROOT.iterdir()}
    environment = {**os.environ, "TMPDIR": str(ROOT)}
    result = subprocess.run(
        [
            "bash",
            str(ROOT / "tools/check-witness-dependency-closure.sh"),
            "--self-test",
            "missing-library-target",
        ],
        cwd=ROOT,
        env=environment,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    expected = EXPECTED_DIAGNOSTIC["self-test-parent-boundary"]
    if result.returncode == 0 or expected not in result.stdout:
        fail(
            "self-test parent control failed for wrong reason: "
            f"status={result.returncode} output={result.stdout!r}"
        )
    after = {entry.name for entry in ROOT.iterdir()}
    if after != before:
        fail(
            "self-test parent refusal created a child path: "
            f"added={sorted(after - before)} removed={sorted(before - after)}"
        )
    print(
        "self_test_red case=self-test-parent-boundary "
        "parent_prevalidated=1 child_paths_created=0 "
        f"failure={expected}"
    )


def run_self_test(case):
    temporary_parent = validated_temp_parent("self-test scratch", ROOT)
    subject_data = evaluate(ROOT, False)
    temporary = tempfile.TemporaryDirectory(
        prefix="phase285-witness-closure.", dir=temporary_parent
    )
    container = pathlib.Path(temporary.name).resolve()
    diagnostic = None
    identity_count = 0
    try:
        scratch, identities = build_projection(subject_data, container)
        assert_byte_identities(identities)
        identity_count = len(identities)
        scratch_data = evaluate(scratch, False)
        if case == "metadata-harness-boundary":
            boundary_tmp = scratch / "metadata-harness-boundary"
            boundary_tmp.mkdir()
            previous_tmpdir = os.environ.get("TMPDIR")
            os.environ["TMPDIR"] = str(boundary_tmp)
            try:
                scratch_packages = {
                    package["name"]: package for package in scratch_data["packages"]
                }
                try:
                    package_scoped_metadata(
                        scratch,
                        scratch_data,
                        scratch_packages[PACKAGE]["id"],
                    )
                except ClosureFailure as error:
                    diagnostic = str(error)
                    expected = EXPECTED_DIAGNOSTIC[case]
                    if expected not in diagnostic:
                        fail(
                            f"self-test {case} failed for wrong reason: "
                            f"expected={expected!r} actual={diagnostic!r}"
                        )
                else:
                    fail(f"self-test mutation unexpectedly passed: {case}")
            finally:
                if previous_tmpdir is None:
                    os.environ.pop("TMPDIR", None)
                else:
                    os.environ["TMPDIR"] = previous_tmpdir
            if any(boundary_tmp.iterdir()):
                fail("metadata harness boundary cleanup left a child path")
            boundary_tmp.rmdir()
            if boundary_tmp.exists():
                fail("metadata harness boundary cleanup left its TMPDIR path")
        elif case in {
            "partial-cargo-tree-omission",
            "host-tree-mismatch",
            "all-target-subset-omission",
        }:
            scratch_packages = {
                package["name"]: package for package in scratch_data["packages"]
            }
            root_id = scratch_packages[PACKAGE]["id"]
            if case == "host-tree-mismatch":
                mutation_output = cargo_tree_output(
                    scratch, PACKAGE, "normal", "all"
                )
            else:
                mutation_output = strict_partial_cargo_tree_output(
                    scratch,
                    scratch_data,
                    root_id,
                    rustc_host(scratch),
                )
            diagnostic = expect_mutation_failure(
                scratch,
                case,
                False,
                {
                    "normal-all" if case == "all-target-subset-omission" else "normal":
                    mutation_output
                },
            )
        else:
            mutate(scratch, container, case)
        current_cases = {
            "missing-current-target", "extra-current-target",
            "substituted-current-target", "syntax-invalid-binary-target",
            "type-invalid-binary-target",
        }
        if case in {"syntax-invalid-binary-target", "type-invalid-binary-target"}:
            evaluate(scratch, "current-targets")
            invalid = (
                "fn main( {\n"
                if case == "syntax-invalid-binary-target"
                else 'fn main() { let _: u8 = "not-a-byte"; }\n'
            )
            target = (
                scratch
                / "crates"
                / PACKAGE
                / EXPECTED_BIN_PATHS["swarm-governance-witness-store"]
            )
            target.write_text(invalid, encoding="utf-8")
            diagnostic = expect_mutation_failure(scratch, case, "current-targets")
        elif case in current_cases:
            diagnostic = expect_mutation_failure(scratch, case, "current-targets")
        elif case not in {
            "partial-cargo-tree-omission",
            "host-tree-mismatch",
            "all-target-subset-omission",
            "metadata-harness-boundary",
        }:
            diagnostic = expect_mutation_failure(scratch, case, False)
    finally:
        temporary.cleanup()
        if container.exists():
            fail(f"scratch cleanup failed: {container}")
    print(
        f"self_test_red case={case} subject_copy=exact byte_identities={identity_count} "
        f"target_config_match=1 scratch_removed=1 failure={diagnostic}"
    )


try:
    if MODE == "--library-only":
        evaluate(ROOT, "library-only")
    elif MODE == "--current-targets":
        evaluate(ROOT, "current-targets")
    elif MODE == "--all-targets":
        evaluate(ROOT, "all-targets")
    else:
        selected = (CASE,) if CASE else CASES
        unknown = set(selected) - set(CASES)
        if unknown:
            fail(f"unknown self-test case: {sorted(unknown)}")
        for name in selected:
            if name == "self-test-parent-boundary":
                run_self_test_parent_control()
            else:
                run_self_test(name)
        print(f"self_test executed={len(selected)} passed={len(selected)} failed=0")
except ClosureFailure as error:
    print(f"witness dependency closure failed: {error}", file=sys.stderr)
    raise SystemExit(1)
PY
