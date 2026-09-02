#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

validate_cyclonedx_dir() {
  python3 - "$1" "$2" <<'PY'
import json
import pathlib
import re
import subprocess
import sys
import urllib.parse
import uuid

root = pathlib.Path(sys.argv[1])
# Preserve the caller's lexical absolute path. On macOS /var is a symlink to
# /private/var; cargo-cyclonedx embeds the lexical path supplied at generation
# time, so resolving only during validation would fabricate a package-id drift.
manifest_path = pathlib.Path(sys.argv[2]).absolute()
paths = sorted(set(root.glob("*.cdx.json")) | set(root.glob("*/*.cdx.json")))
if not paths:
    raise SystemExit(f"no CycloneDX JSON files found under {root}")

metadata_process = subprocess.run(
    [
        "cargo",
        "metadata",
        "--locked",
        "--format-version",
        "1",
        "--manifest-path",
        str(manifest_path),
    ],
    cwd=manifest_path.parent,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    text=True,
)
if metadata_process.returncode != 0:
    raise SystemExit(
        f"locked cargo metadata failed for {manifest_path}: "
        f"{metadata_process.stderr.strip()}"
    )
try:
    cargo_metadata = json.loads(metadata_process.stdout)
except json.JSONDecodeError as exc:
    raise SystemExit(f"cargo metadata returned invalid JSON for {manifest_path}: {exc}")
workspace_member_ids = cargo_metadata.get("workspace_members")
packages = cargo_metadata.get("packages")
if not isinstance(workspace_member_ids, list) or not workspace_member_ids:
    raise SystemExit(f"cargo metadata reported no workspace members for {manifest_path}")
if not isinstance(packages, list):
    raise SystemExit(f"cargo metadata packages are missing for {manifest_path}")
resolve = cargo_metadata.get("resolve")
if not isinstance(resolve, dict) or not isinstance(resolve.get("nodes"), list):
    raise SystemExit(f"cargo metadata resolve graph is missing for {manifest_path}")
packages_by_id: dict[str, dict[str, object]] = {}
for index, package in enumerate(packages):
    if not isinstance(package, dict):
        raise SystemExit(f"cargo metadata packages[{index}] is not an object")
    package_id = package.get("id")
    if not isinstance(package_id, str) or not package_id:
        raise SystemExit(f"cargo metadata packages[{index}] has no non-empty id")
    if package_id in packages_by_id:
        raise SystemExit(f"cargo metadata contains duplicate package id {package_id!r}")
    packages_by_id[package_id] = package

resolve_nodes_by_id: dict[str, tuple[str, ...]] = {}
for index, node in enumerate(resolve["nodes"]):
    if not isinstance(node, dict):
        raise SystemExit(f"cargo metadata resolve.nodes[{index}] is not an object")
    node_id = node.get("id")
    dependencies = node.get("deps")
    if not isinstance(node_id, str) or not node_id:
        raise SystemExit(f"cargo metadata resolve.nodes[{index}] has no non-empty id")
    if node_id in resolve_nodes_by_id:
        raise SystemExit(f"cargo metadata resolve graph duplicates node {node_id!r}")
    if not isinstance(dependencies, list):
        raise SystemExit(
            f"cargo metadata resolve node {node_id!r} has invalid dependencies"
        )
    production_dependencies: list[str] = []
    for dependency_index, dependency in enumerate(dependencies):
        if not isinstance(dependency, dict):
            raise SystemExit(
                "cargo metadata resolve node "
                f"{node_id!r} dependency {dependency_index} is not an object"
            )
        package_id = dependency.get("pkg")
        dependency_kinds = dependency.get("dep_kinds")
        if not isinstance(package_id, str) or not package_id:
            raise SystemExit(
                "cargo metadata resolve node "
                f"{node_id!r} dependency {dependency_index} has no package id"
            )
        if not isinstance(dependency_kinds, list) or not dependency_kinds:
            raise SystemExit(
                "cargo metadata resolve node "
                f"{node_id!r} dependency {package_id!r} has no dependency kinds"
            )
        kinds: list[object] = []
        for kind_index, dependency_kind in enumerate(dependency_kinds):
            if not isinstance(dependency_kind, dict):
                raise SystemExit(
                    "cargo metadata resolve node "
                    f"{node_id!r} dependency {package_id!r} kind {kind_index} "
                    "is not an object"
                )
            kind = dependency_kind.get("kind")
            if kind not in (None, "build", "dev"):
                raise SystemExit(
                    "cargo metadata resolve node "
                    f"{node_id!r} dependency {package_id!r} has unknown kind {kind!r}"
                )
            kinds.append(kind)
        # cargo-cyclonedx 0.5.9 excludes a NodeDep only when every resolved
        # dependency kind is development-only. Its --target all mode leaves
        # platform filtering disabled, so this is the complete production/build
        # closure across every target supported by the locked graph.
        if any(kind != "dev" for kind in kinds):
            production_dependencies.append(package_id)
    if len(production_dependencies) != len(set(production_dependencies)):
        raise SystemExit(
            f"cargo metadata resolve node {node_id!r} duplicates a production dependency"
        )
    resolve_nodes_by_id[node_id] = tuple(production_dependencies)

package_ids = set(packages_by_id)
node_ids = set(resolve_nodes_by_id)
if node_ids != package_ids:
    raise SystemExit(
        "cargo metadata package and resolve-node inventories disagree: "
        f"missing_nodes={sorted(package_ids - node_ids)!r}, "
        f"unknown_nodes={sorted(node_ids - package_ids)!r}"
    )
for node_id, dependencies in resolve_nodes_by_id.items():
    unknown = sorted(set(dependencies) - package_ids)
    if unknown:
        raise SystemExit(
            f"cargo metadata resolve node {node_id!r} references unknown packages {unknown!r}"
        )

expected_packages: dict[tuple[str, str], dict[str, object]] = {}
expected_names: set[str] = set()
for member_id in workspace_member_ids:
    package = packages_by_id.get(member_id)
    if not isinstance(package, dict):
        raise SystemExit(f"workspace member {member_id!r} has no cargo metadata package")
    name = package.get("name")
    version = package.get("version")
    if not isinstance(name, str) or not name or not isinstance(version, str) or not version:
        raise SystemExit(f"workspace member {member_id!r} has invalid name/version metadata")
    identity = (name, version)
    if identity in expected_packages:
        raise SystemExit(f"duplicate workspace package identity in cargo metadata: {identity!r}")
    if name in expected_names:
        raise SystemExit(f"workspace package name is not unique for SBOM filename: {name}")
    expected_packages[identity] = package
    expected_names.add(name)


def reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate object key {key!r}")
        result[key] = value
    return result


def reject_nonstandard_constant(value: str) -> None:
    raise ValueError(f"non-standard JSON constant {value}")


def fail(path: pathlib.Path, message: str) -> None:
    raise SystemExit(f"invalid CycloneDX 1.5 SBOM {path}: {message}")


def require_nonempty_string(
    path: pathlib.Path, owner: dict[str, object], field: str, context: str
) -> str:
    value = owner.get(field)
    if not isinstance(value, str) or not value:
        fail(path, f"{context}.{field} must be a non-empty string")
    return value


CYCLONEDX_15_COMPONENT_TYPES = {
    "application",
    "framework",
    "library",
    "container",
    "platform",
    "operating-system",
    "device",
    "device-driver",
    "firmware",
    "file",
    "machine-learning-model",
    "data",
}
CYCLONEDX_15_COMPONENT_SCOPES = {"required", "optional", "excluded"}
CYCLONEDX_15_TOP_LEVEL_KEYS = {
    "bomFormat",
    "specVersion",
    "serialNumber",
    "version",
    "metadata",
    "components",
    "dependencies",
}
CYCLONEDX_15_METADATA_KEYS = {"timestamp", "tools", "component", "properties"}
CYCLONEDX_15_COMPONENT_KEYS = {
    "type",
    "bom-ref",
    "author",
    "name",
    "version",
    "description",
    "scope",
    "hashes",
    "licenses",
    "purl",
    "externalReferences",
    "components",
}
CYCLONEDX_15_HASH_ALGORITHMS = {
    "MD5",
    "SHA-1",
    "SHA-256",
    "SHA-384",
    "SHA-512",
    "SHA3-256",
    "SHA3-384",
    "SHA3-512",
    "BLAKE2b-256",
    "BLAKE2b-384",
    "BLAKE2b-512",
    "BLAKE3",
}
SERIAL_NUMBER = re.compile(
    r"^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)


def require_exact_keys(
    path: pathlib.Path,
    value: dict[str, object],
    required: set[str],
    allowed: set[str],
    context: str,
) -> None:
    actual = set(value)
    missing = sorted(required - actual)
    unknown = sorted(actual - allowed)
    if missing or unknown:
        fail(
            path,
            f"{context} keys violate the compiled cargo-cyclonedx 0.5.9 / "
            f"CycloneDX 1.5 contract: missing={missing!r}, unknown={unknown!r}",
        )


def require_component(
    path: pathlib.Path,
    value: object,
    context: str,
    seen_component_refs: set[str],
) -> dict[str, object]:
    if not isinstance(value, dict):
        fail(path, f"{context} must be an object")
    require_exact_keys(
        path,
        value,
        {"type", "bom-ref", "name", "version", "purl"},
        CYCLONEDX_15_COMPONENT_KEYS,
        context,
    )
    component_type = require_nonempty_string(path, value, "type", context)
    if component_type not in CYCLONEDX_15_COMPONENT_TYPES:
        fail(
            path,
            f"{context}.type {component_type!r} is not allowed by the pinned "
            "CycloneDX 1.5 component-type enum",
        )
    for field in ("bom-ref", "name", "version", "purl"):
        require_nonempty_string(path, value, field, context)
    component_ref = value["bom-ref"]
    if component_ref in seen_component_refs:
        fail(path, f"{context}.bom-ref duplicates {component_ref!r}")
    seen_component_refs.add(component_ref)

    for field in ("author", "description"):
        if field in value and not isinstance(value[field], str):
            fail(path, f"{context}.{field} must be a string")
    scope = value.get("scope")
    if scope is not None and scope not in CYCLONEDX_15_COMPONENT_SCOPES:
        fail(path, f"{context}.scope {scope!r} is not allowed by CycloneDX 1.5")

    hashes = value.get("hashes", [])
    if not isinstance(hashes, list):
        fail(path, f"{context}.hashes must be an array")
    for index, item in enumerate(hashes):
        item_context = f"{context}.hashes[{index}]"
        if not isinstance(item, dict):
            fail(path, f"{item_context} must be an object")
        require_exact_keys(path, item, {"alg", "content"}, {"alg", "content"}, item_context)
        algorithm = require_nonempty_string(path, item, "alg", item_context)
        content = require_nonempty_string(path, item, "content", item_context)
        if algorithm not in CYCLONEDX_15_HASH_ALGORITHMS:
            fail(path, f"{item_context}.alg {algorithm!r} is not allowed by CycloneDX 1.5")
        if re.fullmatch(r"[0-9a-fA-F]+", content) is None:
            fail(path, f"{item_context}.content must be hexadecimal")

    licenses = value.get("licenses", [])
    if not isinstance(licenses, list):
        fail(path, f"{context}.licenses must be an array")
    for index, item in enumerate(licenses):
        item_context = f"{context}.licenses[{index}]"
        if not isinstance(item, dict):
            fail(path, f"{item_context} must be an object")
        require_exact_keys(path, item, {"expression"}, {"expression"}, item_context)
        require_nonempty_string(path, item, "expression", item_context)

    references = value.get("externalReferences", [])
    if not isinstance(references, list):
        fail(path, f"{context}.externalReferences must be an array")
    for index, item in enumerate(references):
        item_context = f"{context}.externalReferences[{index}]"
        if not isinstance(item, dict):
            fail(path, f"{item_context} must be an object")
        require_exact_keys(path, item, {"type", "url"}, {"type", "url"}, item_context)
        require_nonempty_string(path, item, "type", item_context)
        require_nonempty_string(path, item, "url", item_context)

    nested = value.get("components", [])
    if not isinstance(nested, list):
        fail(path, f"{context}.components must be an array")
    for index, item in enumerate(nested):
        require_component(
            path,
            item,
            f"{context}.components[{index}]",
            seen_component_refs,
        )
    return value


def require_package_identity(
    path: pathlib.Path,
    component: dict[str, object],
    package: dict[str, object],
    context: str,
) -> None:
    package_name = package.get("name")
    package_version = package.get("version")
    package_id = package.get("id")
    if component.get("bom-ref") != package_id:
        fail(path, f"{context}.bom-ref must equal locked Cargo package id {package_id!r}")
    if component.get("name") != package_name or component.get("version") != package_version:
        fail(
            path,
            f"{context} identity must equal locked Cargo package "
            f"{package_name}@{package_version}",
        )
    expected_purl = (
        "pkg:cargo/"
        f"{urllib.parse.quote(str(package_name), safe='-._~')}@"
        # packageurl (and cargo-cyclonedx 0.5.9) preserve the SemVer build
        # separator rather than percent-encoding it.
        f"{urllib.parse.quote(str(package_version), safe='-._~+')}"
    )
    if str(component.get("purl", "")).split("?", 1)[0] != expected_purl:
        fail(path, f"{context}.purl must identify {package_name}@{package_version}")


def require_root_target_inventory(
    path: pathlib.Path,
    component: dict[str, object],
    package: dict[str, object],
) -> None:
    package_root = pathlib.Path(str(package.get("manifest_path"))).parent
    package_ref = str(package.get("id"))
    package_name = str(package.get("name"))
    package_version = str(package.get("version"))
    package_purl = (
        "pkg:cargo/"
        f"{urllib.parse.quote(package_name, safe='-._~')}@"
        f"{urllib.parse.quote(package_version, safe='-._~+')}"
    )
    targets = package.get("targets")
    if not isinstance(targets, list):
        fail(path, "locked Cargo package has no target inventory")
    expected: list[dict[str, object]] = []
    for target in targets:
        if not isinstance(target, dict) or not isinstance(target.get("kind"), list):
            fail(path, "locked Cargo package has an invalid target entry")
        kinds = target["kind"]
        if "lib" not in kinds and "bin" not in kinds:
            continue
        target_name = target.get("name")
        source_path = target.get("src_path")
        if not isinstance(target_name, str) or not target_name:
            fail(path, "locked Cargo production target has no non-empty name")
        if not isinstance(source_path, str) or not source_path:
            fail(path, f"locked Cargo target {target_name!r} has no source path")
        try:
            relative_source = pathlib.Path(source_path).relative_to(package_root).as_posix()
        except ValueError:
            fail(path, f"locked Cargo target {target_name!r} escapes its package root")
        index = len(expected)
        expected.append({
            "type": "application" if "bin" in kinds else "library",
            "bom-ref": f"{package_ref} bin-target-{index}",
            "name": target_name,
            "version": package_version,
            "purl": f"{package_purl}?download_url=file://.#{relative_source}",
        })
    actual = component.get("components", [])
    if actual != expected:
        fail(
            path,
            "metadata.component.components disagree with Cargo production-target "
            f"inventory: expected={expected!r}, actual={actual!r}",
        )


seen_packages: dict[tuple[str, str], pathlib.Path] = {}
for path in paths:
    try:
        document = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=reject_duplicate_keys,
            parse_constant=reject_nonstandard_constant,
        )
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        fail(path, f"not valid UTF-8 JSON: {exc}")
    if not isinstance(document, dict):
        fail(path, "top level must be an object")
    if document.get("bomFormat") != "CycloneDX":
        fail(path, "bomFormat must equal 'CycloneDX'")
    if document.get("specVersion") != "1.5":
        fail(path, "specVersion must equal '1.5'")
    require_exact_keys(
        path,
        document,
        CYCLONEDX_15_TOP_LEVEL_KEYS,
        CYCLONEDX_15_TOP_LEVEL_KEYS,
        "document",
    )
    version = document.get("version")
    if isinstance(version, bool) or not isinstance(version, int) or version < 1:
        fail(path, "version must be a positive integer")
    serial = require_nonempty_string(path, document, "serialNumber", "document")
    if SERIAL_NUMBER.fullmatch(serial) is None:
        fail(path, "serialNumber must be a lowercase urn:uuid value")
    try:
        uuid.UUID(serial.removeprefix("urn:uuid:"))
    except ValueError as exc:
        fail(path, f"serialNumber contains an invalid UUID: {exc}")

    metadata = document.get("metadata")
    if not isinstance(metadata, dict):
        fail(path, "metadata must be an object")
    require_exact_keys(
        path,
        metadata,
        {"component"},
        CYCLONEDX_15_METADATA_KEYS,
        "metadata",
    )
    if "timestamp" in metadata:
        require_nonempty_string(path, metadata, "timestamp", "metadata")
    tools = metadata.get("tools", [])
    if not isinstance(tools, list) or len(tools) != 1:
        fail(path, "metadata.tools must contain exactly the pinned cargo-cyclonedx tool")
    for index, tool in enumerate(tools):
        context = f"metadata.tools[{index}]"
        if not isinstance(tool, dict):
            fail(path, f"{context} must be an object")
        require_exact_keys(
            path,
            tool,
            {"vendor", "name", "version"},
            {"vendor", "name", "version"},
            context,
        )
        for field in ("vendor", "name", "version"):
            require_nonempty_string(path, tool, field, context)
    if tools != [{"vendor": "CycloneDX", "name": "cargo-cyclonedx", "version": "0.5.9"}]:
        fail(path, "metadata.tools must identify cargo-cyclonedx 0.5.9 exactly")
    properties = metadata.get("properties", [])
    if not isinstance(properties, list):
        fail(path, "metadata.properties must be an array")
    for index, prop in enumerate(properties):
        context = f"metadata.properties[{index}]"
        if not isinstance(prop, dict):
            fail(path, f"{context} must be an object")
        require_exact_keys(path, prop, {"name", "value"}, {"name", "value"}, context)
        require_nonempty_string(path, prop, "name", context)
        if not isinstance(prop.get("value"), str):
            fail(path, f"{context}.value must be a string")
    if properties != [{"name": "cdx:rustc:sbom:target:all_targets", "value": "true"}]:
        fail(path, "metadata.properties must prove cargo-cyclonedx --target all")

    seen_component_refs: set[str] = set()
    metadata_component = metadata.get("component")
    metadata_component = require_component(
        path,
        metadata_component,
        "metadata.component",
        seen_component_refs,
    )
    component_name = require_nonempty_string(
        path, metadata_component, "name", "metadata.component"
    )
    component_version = require_nonempty_string(
        path, metadata_component, "version", "metadata.component"
    )
    component_purl = require_nonempty_string(
        path, metadata_component, "purl", "metadata.component"
    )
    identity = (component_name, component_version)
    if identity in seen_packages:
        fail(
            path,
            "metadata.component package identity is duplicated by "
            f"{seen_packages[identity]}: {component_name}@{component_version}",
        )
    seen_packages[identity] = path
    expected_filename = f"{component_name}.cdx.json"
    if path.name != expected_filename:
        fail(
            path,
            f"filename must be {expected_filename!r} for metadata.component package",
        )
    expected_package = expected_packages.get(identity)
    expected_purl = "pkg:cargo/" + urllib.parse.quote(component_name, safe="-._~")
    expected_purl += "@" + urllib.parse.quote(component_version, safe="-._~+")
    if component_purl.split("?", 1)[0] != expected_purl:
        fail(
            path,
            f"metadata.component.purl must identify {component_name}@{component_version}",
        )

    components = document.get("components")
    if not isinstance(components, list):
        fail(path, "components must be an array")
    components_by_ref: dict[str, dict[str, object]] = {}
    for index, component in enumerate(components):
        component = require_component(
            path,
            component,
            f"components[{index}]",
            seen_component_refs,
        )
        components_by_ref[str(component["bom-ref"])] = component

    dependencies = document.get("dependencies")
    if not isinstance(dependencies, list) or not dependencies:
        fail(path, "dependencies must be a non-empty array")
    dependency_edges: dict[str, set[str]] = {}
    for index, dependency in enumerate(dependencies):
        if not isinstance(dependency, dict):
            fail(path, f"dependencies[{index}] must be an object")
        context = f"dependencies[{index}]"
        require_exact_keys(path, dependency, {"ref"}, {"ref", "dependsOn"}, context)
        dependency_ref = require_nonempty_string(path, dependency, "ref", context)
        if dependency_ref in dependency_edges:
            fail(path, f"{context}.ref duplicates {dependency_ref!r}")
        # cargo-cyclonedx 0.5.9 omits `dependsOn` for leaves rather than
        # serializing an empty array. Both forms represent an empty edge set.
        depends_on = dependency.get("dependsOn", [])
        if not isinstance(depends_on, list) or not all(
            isinstance(item, str) and item for item in depends_on
        ):
            fail(path, f"{context}.dependsOn must be an array of non-empty strings")
        if len(depends_on) != len(set(depends_on)):
            fail(path, f"{context}.dependsOn duplicates a dependency ref")
        dependency_edges[dependency_ref] = set(depends_on)

    # Root identities outside the locked workspace are reported by the final
    # inventory comparison. Known roots receive the stronger exact resolve-graph
    # validation below, including every reachable external dependency.
    if expected_package is None:
        continue
    require_package_identity(path, metadata_component, expected_package, "metadata.component")
    require_root_target_inventory(path, metadata_component, expected_package)
    root_id = str(expected_package["id"])
    reachable: set[str] = set()
    pending = [root_id]
    while pending:
        package_id = pending.pop()
        if package_id in reachable:
            continue
        reachable.add(package_id)
        pending.extend(resolve_nodes_by_id[package_id])

    expected_component_refs = reachable - {root_id}
    actual_component_refs = set(components_by_ref)
    if actual_component_refs != expected_component_refs:
        fail(
            path,
            f"component refs disagree with locked Cargo resolve closure for {root_id!r}: "
            f"missing={sorted(expected_component_refs - actual_component_refs)!r}, "
            f"unexpected={sorted(actual_component_refs - expected_component_refs)!r}",
        )
    for package_id, component in components_by_ref.items():
        if component.get("components"):
            fail(path, f"dependency component {package_id!r} contains nested target components")
        require_package_identity(path, component, packages_by_id[package_id], "component")

    actual_dependency_refs = set(dependency_edges)
    if actual_dependency_refs != reachable:
        fail(
            path,
            f"dependency refs disagree with locked Cargo resolve closure for {root_id!r}: "
            f"missing={sorted(reachable - actual_dependency_refs)!r}, "
            f"unexpected={sorted(actual_dependency_refs - reachable)!r}",
        )
    for package_id in sorted(reachable):
        expected_edges = set(resolve_nodes_by_id[package_id])
        actual_edges = dependency_edges[package_id]
        if actual_edges != expected_edges:
            fail(
                path,
                f"dependency graph disagrees with locked cargo metadata for "
                f"{package_id!r}: missing={sorted(expected_edges - actual_edges)!r}, "
                f"unexpected={sorted(actual_edges - expected_edges)!r}",
            )

expected_identities = set(expected_packages)
seen_identities = set(seen_packages)
missing = sorted(expected_identities - seen_identities)
unexpected = sorted(seen_identities - expected_identities)
if missing or unexpected:
    raise SystemExit(
        "CycloneDX workspace inventory disagrees with locked cargo metadata: "
        f"missing={missing!r}, unexpected={unexpected!r}"
    )
expected_files = {f"{name}.cdx.json" for name, _version in expected_identities}
actual_files = {path.name for path in paths}
if actual_files != expected_files:
    raise SystemExit(
        "CycloneDX filename inventory disagrees with locked cargo metadata: "
        f"missing={sorted(expected_files - actual_files)!r}, "
        f"unexpected={sorted(actual_files - expected_files)!r}"
    )

print(
    f"validated {len(paths)} CycloneDX 1.5 SBOM file(s) for "
    f"{len(expected_packages)} locked workspace package(s)"
)
PY
}

reject_repository_cyclonedx_alias() {
  python3 - "$ROOT_DIR" <<'PY'
import pathlib
import sys
import tomllib

root = pathlib.Path(sys.argv[1])
for relative in (".cargo/config", ".cargo/config.toml"):
    path = root / relative
    if not path.exists():
        continue
    try:
        config = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise SystemExit(f"cannot parse repository Cargo config {relative}: {exc}")
    aliases = config.get("alias", {})
    if isinstance(aliases, dict) and "cyclonedx" in aliases:
        raise SystemExit(
            f"repository Cargo alias 'cyclonedx' is forbidden in {relative}; "
            "it can shadow the installed external command"
        )
PY
}

resolve_cyclonedx_binary() {
  local candidate="${CARGO_CYCLONEDX_BIN:-}"
  local candidate_dir

  if [[ -z "$candidate" ]]; then
    if ! candidate="$(command -v cargo-cyclonedx)"; then
      echo "cargo-cyclonedx 0.5.9 is required but is not installed" >&2
      return 1
    fi
  fi
  if [[ "$candidate" != /* ]]; then
    candidate="$(pwd -P)/$candidate"
  fi
  if [[ ! -x "$candidate" ]]; then
    echo "resolved cargo-cyclonedx binary is not executable: $candidate" >&2
    return 1
  fi
  candidate_dir="$(cd -- "$(dirname -- "$candidate")" && pwd -P)"
  printf '%s/%s\n' "$candidate_dir" "$(basename -- "$candidate")"
}

if [[ "${1:-}" == "--validate-dir" ]]; then
  if [[ "$#" -lt 2 || "$#" -gt 3 ]]; then
    echo "usage: $0 --validate-dir <directory> [manifest-path]" >&2
    exit 2
  fi
  validate_cyclonedx_dir "$2" "${3:-$ROOT_DIR/Cargo.toml}"
  exit 0
fi

OUTPUT_DIR="${1:-$ROOT_DIR/artifacts/sbom}"
CARGO_CYCLONEDX_VERSION="${CARGO_CYCLONEDX_VERSION:-0.5.9}"

reject_repository_cyclonedx_alias
CARGO_CYCLONEDX_BIN_PATH="$(resolve_cyclonedx_binary)"
actual_cyclonedx_version="$("$CARGO_CYCLONEDX_BIN_PATH" cyclonedx --version)"
if [[ "$actual_cyclonedx_version" != \
  "cargo-cyclonedx-cyclonedx $CARGO_CYCLONEDX_VERSION" ]]; then
  echo "cargo-cyclonedx version mismatch: expected $CARGO_CYCLONEDX_VERSION, got '$actual_cyclonedx_version'" >&2
  exit 1
fi

mkdir -p "$OUTPUT_DIR"
find "$OUTPUT_DIR" -maxdepth 1 -name '*.cdx.json' -delete

pushd "$ROOT_DIR" >/dev/null
find "$ROOT_DIR/crates" -mindepth 2 -maxdepth 2 \
  \( -name '*.cdx.json' -o -name 'swarm-team-six.json' \) -delete
"$CARGO_CYCLONEDX_BIN_PATH" cyclonedx \
  --manifest-path Cargo.toml --format json --spec-version 1.5 --target all --quiet
validate_cyclonedx_dir "$ROOT_DIR/crates" "$ROOT_DIR/Cargo.toml"

count=0
while IFS= read -r -d '' sbom; do
  cp "$sbom" "$OUTPUT_DIR/$(basename "$sbom")"
  rm -f "$sbom"
  count=$((count + 1))
done < <(find "$ROOT_DIR/crates" -mindepth 2 -maxdepth 2 -name '*.cdx.json' -print0 | sort -z)
find "$ROOT_DIR/crates" -mindepth 2 -maxdepth 2 -name 'swarm-team-six.json' -delete
popd >/dev/null

if [[ "$count" -eq 0 ]]; then
  echo "no SBOM files were generated" >&2
  exit 1
fi

echo "generated $count SBOM files in $OUTPUT_DIR"
