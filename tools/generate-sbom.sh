#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

validate_cyclonedx_dir() {
  python3 - "$1" <<'PY'
import json
import pathlib
import sys
import uuid

root = pathlib.Path(sys.argv[1])
paths = sorted(set(root.glob("*.cdx.json")) | set(root.glob("*/*.cdx.json")))
if not paths:
    raise SystemExit(f"no CycloneDX JSON files found under {root}")


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
    require_component(path, metadata.get("component"), "metadata.component")

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

print(f"validated {len(paths)} CycloneDX 1.5 SBOM file(s)")
PY
}

if [[ "${1:-}" == "--validate-dir" ]]; then
  if [[ "$#" -ne 2 ]]; then
    echo "usage: $0 --validate-dir <directory>" >&2
    exit 2
  fi
  validate_cyclonedx_dir "$2"
  exit 0
fi

OUTPUT_DIR="${1:-$ROOT_DIR/artifacts/sbom}"

mkdir -p "$OUTPUT_DIR"
find "$OUTPUT_DIR" -maxdepth 1 -name '*.cdx.json' -delete

pushd "$ROOT_DIR" >/dev/null
find "$ROOT_DIR/crates" -mindepth 2 -maxdepth 2 \
  \( -name '*.cdx.json' -o -name 'swarm-team-six.json' \) -delete
cargo cyclonedx --manifest-path Cargo.toml --format json --spec-version 1.5 --quiet
validate_cyclonedx_dir "$ROOT_DIR/crates"

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
