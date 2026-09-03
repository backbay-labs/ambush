#!/usr/bin/env python3
"""Render the authoring YAML to the byte shape `generate_perch_openapi` must emit.

WHAT THIS IS FOR
    `docs/plans/ambush-ui/build/openapi/perch-operator-v1.yaml` is the reviewable
    authoring source: it carries comments, and comments are what make a 2,000-line
    contract readable. `docs/openapi/perch-operator-v1.json` is the artifact CI
    gates, and it is byte-compared against a Rust generator. No serializer emits
    comments, so those cannot be the same file. This script is the bridge between
    them, and it is the handoff to whoever writes `generate_perch_openapi.rs`: the
    JSON it produces is exactly the bytes that binary has to produce.

WHY THESE EXACT SERIALIZER SETTINGS
    `generate_platform_openapi.rs:33` renders with `serde_json::to_string_pretty`
    and writes `rendered + "\\n"` (`:48`). The workspace pins `serde_json = "1"`
    with no `preserve_order` feature (`Cargo.toml:75`), so `serde_json::Value`'s
    object is a `BTreeMap` and keys come out lexicographically sorted; the pretty
    printer uses two-space indent, `": "` after a key, and escapes nothing outside
    the JSON-mandated set.

    `json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False) + "\\n"` is the
    Python spelling of exactly that, and THIS SCRIPT PROVES IT rather than asserting
    it: `--self-test` round-trips the real committed
    `docs/openapi/v2-platform-openapi.json` (40 KB, three non-ASCII bytes) through
    parse-then-render and requires byte equality with the file on disk. The
    self-test runs before every render and a failure aborts, because a renderer that
    silently drifts from the serializer would hand the Rust author a target that
    can never be hit.

NOT A CI GATE, ON PURPOSE
    It needs PyYAML, and `tools/check-gates-wired.sh:44-47` records that CI's
    ubuntu-latest is guaranteed only plain python3 and that no wired gate depends on
    PyYAML. It lives under `docs/plans/` and is run by hand. The gate is
    `tools/check-perch-openapi.sh`, which parses no YAML at all.

USAGE
    python3 render-perch-openapi.py --self-test
    python3 render-perch-openapi.py --check        # rendered == committed JSON?
    python3 render-perch-openapi.py --write
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent
YAML_PATH = HERE / "perch-operator-v1.yaml"
JSON_PATH = HERE / "perch-operator-v1.json"
# Four levels up from build/openapi/ is docs/plans/ambush-ui/build -> ... -> repo root.
REPO_ROOT = HERE.parents[4]
PLATFORM_SPEC = REPO_ROOT / "docs" / "openapi" / "v2-platform-openapi.json"


def render(obj: object) -> str:
    """The one place the byte shape is defined."""
    return json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def self_test() -> None:
    """Prove `render` reproduces serde_json::to_string_pretty over a real artifact.

    Refuses to pass silently: a missing platform spec is a failure, not a skip.
    """
    if not PLATFORM_SPEC.is_file():
        sys.exit(
            f"self-test: {PLATFORM_SPEC} is missing; refusing to render against an "
            "unproven byte shape"
        )
    raw = PLATFORM_SPEC.read_bytes()
    if len(raw) < 1024:
        sys.exit(f"self-test: {PLATFORM_SPEC} is {len(raw)} bytes; too small to prove anything")
    again = render(json.loads(raw)).encode("utf-8")
    if again != raw:
        sys.exit(
            "self-test FAILED: parse-then-render of the committed platform spec is not "
            "byte-identical to the file serde_json wrote. The Python spelling of "
            "serde_json::to_string_pretty has drifted; fix `render` before using this "
            "script to produce a generator target."
        )
    non_ascii = sum(1 for b in raw if b > 127)
    print(
        f"self-test OK: {PLATFORM_SPEC.name} ({len(raw)} bytes, {non_ascii} non-ASCII) "
        "round-trips byte-identically"
    )


def load_yaml() -> object:
    try:
        import yaml  # type: ignore
    except ImportError:
        sys.exit(
            "PyYAML is required to read the authoring source. This script is run by "
            "hand, not in CI (see the module docstring): pip install pyyaml==6.0.2"
        )
    if not YAML_PATH.is_file():
        sys.exit(f"missing authoring source {YAML_PATH}")
    with YAML_PATH.open(encoding="utf-8") as handle:
        doc = yaml.safe_load(handle)
    if not isinstance(doc, dict) or "openapi" not in doc:
        sys.exit(f"{YAML_PATH} did not parse to an OpenAPI document")
    return doc


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--self-test", action="store_true", help="prove the byte shape only")
    group.add_argument("--check", action="store_true", help="fail if the committed JSON is stale")
    group.add_argument("--write", action="store_true", help="regenerate the committed JSON")
    args = parser.parse_args()

    self_test()
    if args.self_test:
        return 0

    rendered = render(load_yaml())

    if args.write:
        JSON_PATH.write_text(rendered, encoding="utf-8")
        print(f"wrote {JSON_PATH} ({len(rendered.encode('utf-8'))} bytes)")
        return 0

    if not JSON_PATH.is_file():
        print(f"::error::{JSON_PATH} is missing", file=sys.stderr)
        return 1
    committed = JSON_PATH.read_text(encoding="utf-8")
    if committed != rendered:
        print(
            "::error::perch-operator-v1.json is stale against perch-operator-v1.yaml; "
            "run render-perch-openapi.py --write",
            file=sys.stderr,
        )
        return 1
    print("perch-operator-v1.json matches perch-operator-v1.yaml")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
