#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

validate_cyclonedx_dir() {
  python3 - "$1" "$2" <<'PY'
import json
import pathlib
import subprocess
import sys
import urllib.parse
import uuid

root = pathlib.Path(sys.argv[1])
manifest_path = pathlib.Path(sys.argv[2]).resolve()
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
        "--no-deps",
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
packages_by_id = {
    package.get("id"): package for package in packages if isinstance(package, dict)
}
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


def require_component(path: pathlib.Path, value: object, context: str) -> None:
    if not isinstance(value, dict):
        fail(path, f"{context} must be an object")
    for field in ("type", "bom-ref", "name", "version"):
        require_nonempty_string(path, value, field, context)


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
    version = document.get("version")
    if isinstance(version, bool) or not isinstance(version, int) or version < 1:
        fail(path, "version must be a positive integer")
    serial = require_nonempty_string(path, document, "serialNumber", "document")
    if not serial.startswith("urn:uuid:"):
        fail(path, "serialNumber must be a urn:uuid value")
    try:
        uuid.UUID(serial.removeprefix("urn:uuid:"))
    except ValueError as exc:
        fail(path, f"serialNumber contains an invalid UUID: {exc}")

    metadata = document.get("metadata")
    if not isinstance(metadata, dict):
        fail(path, "metadata must be an object")
    metadata_component = metadata.get("component")
    require_component(path, metadata_component, "metadata.component")
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
    expected_purl = (
        "pkg:cargo/"
        f"{urllib.parse.quote(component_name, safe='-._~')}@"
        f"{urllib.parse.quote(component_version, safe='-._~')}"
    )
    if component_purl.split("?", 1)[0] != expected_purl:
        fail(
            path,
            f"metadata.component.purl must identify {component_name}@{component_version}",
        )

    components = document.get("components")
    if not isinstance(components, list) or not components:
        fail(path, "components must be a non-empty array")
    for index, component in enumerate(components):
        require_component(path, component, f"components[{index}]")

    dependencies = document.get("dependencies")
    if not isinstance(dependencies, list) or not dependencies:
        fail(path, "dependencies must be a non-empty array")
    for index, dependency in enumerate(dependencies):
        if not isinstance(dependency, dict):
            fail(path, f"dependencies[{index}] must be an object")
        require_nonempty_string(path, dependency, "ref", f"dependencies[{index}]")
        # cargo-cyclonedx 0.5.9 omits `dependsOn` for leaves rather than
        # serializing an empty array. Both forms represent an empty edge set.
        depends_on = dependency.get("dependsOn", [])
        if not isinstance(depends_on, list) or not all(
            isinstance(item, str) and item for item in depends_on
        ):
            fail(path, f"dependencies[{index}].dependsOn must be an array of non-empty strings")

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
  --manifest-path Cargo.toml --format json --spec-version 1.5 --quiet
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
