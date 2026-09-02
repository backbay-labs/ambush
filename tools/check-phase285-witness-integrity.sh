#!/usr/bin/env bash
# Local frozen-tree integrity boundary. The root integrator must retain the
# expected launcher and manifest digests out of tree and verify them before use.
# This does not defend against coordinated mutation of every repository file
# and does not replace deferred external App enforcement.
set -euo pipefail

raw_self="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)/$(basename -- "${BASH_SOURCE[0]}")"
[ ! -L "$raw_self" ] || { echo "phase285-integrity: launcher symlink refused" >&2; exit 1; }
root="$(cd -- "$(dirname -- "$raw_self")/.." && pwd -P)"
launcher="$root/tools/check-phase285-witness-integrity.sh"
manifest="$root/tools/fixtures/phase285-witness-integrity.json"
[ "$raw_self" = "$launcher" ] || { echo "phase285-integrity: launcher path differs" >&2; exit 1; }
[ ! -L "$manifest" ] || { echo "phase285-integrity: manifest symlink refused" >&2; exit 1; }

expected_launcher_sha="${PHASE285_WITNESS_INTEGRITY_LAUNCHER_SHA256:?root-supplied launcher SHA-256 required}"
expected_manifest_sha="${PHASE285_WITNESS_INTEGRITY_MANIFEST_SHA256:?root-supplied manifest SHA-256 required}"
for value in "$expected_launcher_sha" "$expected_manifest_sha"; do
  [[ "$value" =~ ^[0-9a-f]{64}$ ]] || { echo "phase285-integrity: expected digest malformed" >&2; exit 1; }
done
actual_launcher_sha="$(shasum -a 256 "$launcher" | awk '{print $1}')"
actual_manifest_sha="$(shasum -a 256 "$manifest" | awk '{print $1}')"
[ "$actual_launcher_sha" = "$expected_launcher_sha" ] || { echo "phase285-integrity: launcher digest differs" >&2; exit 1; }
[ "$actual_manifest_sha" = "$expected_manifest_sha" ] || { echo "phase285-integrity: manifest digest differs" >&2; exit 1; }

checker="$({ python3 -I - "$root" "$launcher" "$manifest" <<'PY'
import hashlib, json, pathlib, stat, sys

root, launcher, manifest = map(pathlib.Path, sys.argv[1:])
root = root.resolve(strict=True)
expected_launcher = root / "tools/check-phase285-witness-integrity.sh"
expected_manifest = root / "tools/fixtures/phase285-witness-integrity.json"
expected_checker = root / "tools/check-phase285-witness-conformance.sh"

def exact_regular(path, expected, name):
    if path != expected or path.is_symlink():
        raise SystemExit(f"phase285-integrity: {name} path or symlink differs")
    mode = path.lstat().st_mode
    if not stat.S_ISREG(mode) or path.resolve(strict=True) != expected:
        raise SystemExit(f"phase285-integrity: {name} is not the exact regular file")

exact_regular(launcher, expected_launcher, "launcher")
exact_regular(manifest, expected_manifest, "manifest")
raw = manifest.read_bytes()
if not raw or len(raw) > 4096 or raw.count(b"\n") != 1 or not raw.endswith(b"\n"):
    raise SystemExit("phase285-integrity: manifest framing differs")

def reject_constant(value):
    raise ValueError(f"non-RFC JSON constant rejected: {value}")

try:
    value = json.loads(raw, parse_constant=reject_constant)
except (json.JSONDecodeError, ValueError) as error:
    raise SystemExit("phase285-integrity: manifest JSON differs") from error
canonical = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode() + b"\n"
if raw != canonical:
    raise SystemExit("phase285-integrity: manifest is not canonical JSON")
if not isinstance(value, dict) or set(value) != {"files", "schema_version", "threat_model"}:
    raise SystemExit("phase285-integrity: manifest field inventory differs")
if value["schema_version"] != 1:
    raise SystemExit("phase285-integrity: manifest schema differs")
expected_threat = {
    "protects": "local_frozen_tree_root_integrator_integrity",
    "does_not_protect": [
        "coordinated_mutation_of_all_repository_files",
        "deferred_external_app_enforcement",
    ],
}
if value["threat_model"] != expected_threat:
    raise SystemExit("phase285-integrity: threat model differs")
files = value["files"]
if not isinstance(files, list) or len(files) != 1:
    raise SystemExit("phase285-integrity: manifest entry cardinality differs")
entry = files[0]
if not isinstance(entry, dict) or set(entry) != {"path", "sha256"}:
    raise SystemExit("phase285-integrity: manifest entry fields differ")
if entry["path"] != "tools/check-phase285-witness-conformance.sh":
    raise SystemExit("phase285-integrity: checker path is not the exact canonical path")
digest = entry["sha256"]
if not isinstance(digest, str) or len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest):
    raise SystemExit("phase285-integrity: checker digest malformed")
checker = root / entry["path"]
exact_regular(checker, expected_checker, "checker")
if hashlib.sha256(checker.read_bytes()).hexdigest() != digest:
    raise SystemExit("phase285-integrity: checker blob digest differs")
print(checker)
PY
} 2>&1)" || { printf '%s\n' "$checker" >&2; exit 1; }

write_execution_sentinel() {
  local sentinel="${PHASE285_WITNESS_INTEGRITY_EXECUTION_SENTINEL:-}"
  [ -n "$sentinel" ] || return 0
  python3 -I - "$sentinel" "$launcher" "$manifest" "$checker" \
    "$actual_launcher_sha" "$actual_manifest_sha" <<'PY'
import json, pathlib, sys
sentinel, launcher, manifest, checker = map(pathlib.Path, sys.argv[1:5])
launcher_sha, manifest_sha = sys.argv[5:7]
if not sentinel.is_absolute() or not sentinel.parent.resolve(strict=True).is_dir() or sentinel.exists():
    raise SystemExit("phase285-integrity: execution sentinel path differs")
row = {
    "checker": str(checker),
    "launcher": str(launcher),
    "launcher_sha256": launcher_sha,
    "manifest": str(manifest),
    "manifest_sha256": manifest_sha,
    "status": "verified_before_execution",
}
with sentinel.open("x") as output:
    output.write(json.dumps(row, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n")
PY
}

run_integrity_self_test() {
  python3 -I - "$root" "$launcher" "$manifest" "$checker" \
    "$expected_launcher_sha" "$expected_manifest_sha" <<'PY'
import hashlib, json, os, pathlib, re, shutil, subprocess, sys, tempfile

root, launcher, manifest, checker = map(pathlib.Path, sys.argv[1:5])
expected_launcher_sha, expected_manifest_sha = sys.argv[5:7]

def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode() + b"\n"

def external_run(test_root, launcher_sha, manifest_sha, arguments, sentinel):
    candidate_launcher = test_root / "tools/check-phase285-witness-integrity.sh"
    candidate_manifest = test_root / "tools/fixtures/phase285-witness-integrity.json"
    if not candidate_launcher.exists() or digest(candidate_launcher) != launcher_sha:
        return "external_launcher_hash", None
    if not candidate_manifest.exists() or digest(candidate_manifest) != manifest_sha:
        return "external_manifest_hash", None
    environment = os.environ.copy()
    environment["PHASE285_WITNESS_INTEGRITY_LAUNCHER_SHA256"] = launcher_sha
    environment["PHASE285_WITNESS_INTEGRITY_MANIFEST_SHA256"] = manifest_sha
    environment["PHASE285_WITNESS_INTEGRITY_EXECUTION_SENTINEL"] = str(sentinel)
    result = subprocess.run(
        ["bash", str(candidate_launcher), *arguments],
        cwd=test_root,
        env=environment,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    return "executed", result

def make_root(parent, name):
    target = parent / name
    (target / "tools/fixtures").mkdir(parents=True)
    shutil.copy2(launcher, target / "tools/check-phase285-witness-integrity.sh")
    shutil.copy2(manifest, target / "tools/fixtures/phase285-witness-integrity.json")
    shutil.copy2(checker, target / "tools/check-phase285-witness-conformance.sh")
    return target

def update_manifest(target):
    manifest_path = target / "tools/fixtures/phase285-witness-integrity.json"
    value = json.loads(manifest_path.read_bytes())
    value["files"][0]["sha256"] = digest(target / "tools/check-phase285-witness-conformance.sh")
    manifest_path.write_bytes(canonical(value))

def replace_function(text, name, next_name, replacement):
    start = text.index(f"\n{name}() {{") + 1
    end = text.index(f"\n{next_name}() {{", start)
    return text[:start] + replacement + "\n\n" + text[end + 1:]

with tempfile.TemporaryDirectory(prefix="phase285-integrity-selftest.") as temporary:
    temporary = pathlib.Path(temporary).resolve(strict=True)
    positive_sentinel = temporary / "positive-executed.json"
    status, result = external_run(root, expected_launcher_sha, expected_manifest_sha, ["--self-test"], positive_sentinel)
    if status != "executed" or result.returncode != 0 or not positive_sentinel.is_file():
        raise SystemExit(f"phase285-integrity: positive checker execution failed: {status} {getattr(result, 'returncode', None)}")

    mutations = []

    target = make_root(temporary, "no-op-wiring")
    path = target / "tools/check-phase285-witness-conformance.sh"
    text = path.read_text()
    text = replace_function(text, "validate_release_probe_wiring", "release_probe_ledger_validator", "validate_release_probe_wiring() { return 0; }")
    path.write_text(text); update_manifest(target)
    mutations.append(("no_op_validate_release_probe_wiring", target, expected_launcher_sha, expected_manifest_sha))

    target = make_root(temporary, "weak-receipt-refreshed")
    path = target / "tools/check-phase285-witness-conformance.sh"
    text = path.read_text()
    old_digest = re.search(r'"validate_release_probe_runtime_receipt": "([0-9a-f]{64})"', text).group(1)
    weakened = "validate_release_probe_runtime_receipt() { return 0; }\n"
    text = replace_function(text, "validate_release_probe_runtime_receipt", "run_release_hook_probe", weakened.rstrip())
    new_digest = hashlib.sha256(weakened.encode()).hexdigest()
    text = text.replace(old_digest, new_digest, 1)
    path.write_text(text); update_manifest(target)
    mutations.append(("weak_receipt_refreshed_local_digest", target, expected_launcher_sha, expected_manifest_sha))

    target = make_root(temporary, "printf-v-receipt")
    path = target / "tools/check-phase285-witness-conformance.sh"
    text = path.read_text()
    old_digest = re.search(r'"record_release_probe_runtime_receipt": "([0-9a-f]{64})"', text).group(1)
    start = text.index("\nrecord_release_probe_runtime_receipt() {") + 1
    end = text.index("\nvalidate_release_probe_runtime_receipt() {", start)
    body = text[start:end]
    body = body.replace('  PHASE285_RELEASE_PROBE_RECEIPT_ROOT="$(cd "$root" && pwd -P)"\n', '  printf -v PHASE285_RELEASE_PROBE_RECEIPT_ROOT "%s" "$(cd "$root" && pwd -P)"\n')
    body = body.replace('  PHASE285_RELEASE_PROBE_RECEIPT_TOKEN="$token"\n', '  printf -v PHASE285_RELEASE_PROBE_RECEIPT_TOKEN "%s" "$token"\n')
    body = body.replace('  PHASE285_RELEASE_PROBE_RECEIPT_SHA="$sha"\n', '  printf -v PHASE285_RELEASE_PROBE_RECEIPT_SHA "%s" "$sha"\n')
    text = text[:start] + body + text[end:]
    text = text.replace(old_digest, hashlib.sha256(body.encode()).hexdigest(), 1)
    text = text.replace("if len(assignments) != 2:", "if len(assignments) != 1:", 1)
    path.write_text(text); update_manifest(target)
    mutations.append(("alternative_printf_v_receipt_write", target, expected_launcher_sha, expected_manifest_sha))

    target = make_root(temporary, "checker-omitted")
    (target / "tools/check-phase285-witness-conformance.sh").unlink()
    mutations.append(("checker_omitted", target, expected_launcher_sha, expected_manifest_sha))

    target = make_root(temporary, "checker-substituted")
    (target / "tools/check-phase285-witness-conformance.sh").write_text("#!/bin/sh\nexit 0\n")
    mutations.append(("checker_substituted", target, expected_launcher_sha, expected_manifest_sha))

    target = make_root(temporary, "checker-alone")
    with (target / "tools/check-phase285-witness-conformance.sh").open("a") as output: output.write("\n")
    mutations.append(("checker_updated_alone", target, expected_launcher_sha, expected_manifest_sha))

    target = make_root(temporary, "manifest-alone")
    value = json.loads((target / "tools/fixtures/phase285-witness-integrity.json").read_bytes())
    value["files"][0]["sha256"] = "0" * 64
    (target / "tools/fixtures/phase285-witness-integrity.json").write_bytes(canonical(value))
    mutations.append(("manifest_updated_alone", target, expected_launcher_sha, expected_manifest_sha))

    for name in ["duplicate", "unknown", "alias"]:
        target = make_root(temporary, f"manifest-{name}")
        manifest_path = target / "tools/fixtures/phase285-witness-integrity.json"
        value = json.loads(manifest_path.read_bytes())
        if name == "duplicate": value["files"].append(dict(value["files"][0]))
        elif name == "unknown": value["unknown"] = "forbidden"
        else: value["files"][0]["path"] = "tools/./check-phase285-witness-conformance.sh"
        manifest_path.write_bytes(canonical(value))
        mutations.append((f"manifest_{name}", target, expected_launcher_sha, digest(manifest_path)))

    target = make_root(temporary, "checker-symlink")
    checker_path = target / "tools/check-phase285-witness-conformance.sh"
    checker_path.unlink(); checker_path.symlink_to(checker)
    mutations.append(("checker_symlink", target, expected_launcher_sha, expected_manifest_sha))

    target = make_root(temporary, "manifest-symlink")
    manifest_path = target / "tools/fixtures/phase285-witness-integrity.json"
    alternate = target / "tools/fixtures/alternate.json"
    manifest_path.rename(alternate); manifest_path.symlink_to(alternate.name)
    mutations.append(("manifest_symlink", target, expected_launcher_sha, expected_manifest_sha))

    target = make_root(temporary, "launcher-symlink")
    launcher_path = target / "tools/check-phase285-witness-integrity.sh"
    alternate = target / "tools/check-phase285-witness-integrity.actual.sh"
    launcher_path.rename(alternate); launcher_path.symlink_to(alternate.name)
    mutations.append(("launcher_symlink", target, expected_launcher_sha, expected_manifest_sha))

    target = make_root(temporary, "launcher-alone")
    with (target / "tools/check-phase285-witness-integrity.sh").open("a") as output: output.write("\n")
    mutations.append(("launcher_updated_alone", target, expected_launcher_sha, expected_manifest_sha))

    killed = 0
    for name, target, launcher_sha, manifest_sha in mutations:
        sentinel = target / "must-not-execute.json"
        status, result = external_run(target, launcher_sha, manifest_sha, ["--self-test"], sentinel)
        if status == "executed" and result.returncode == 0:
            raise SystemExit(f"phase285-integrity: mutation survived: {name}")
        if sentinel.exists():
            raise SystemExit(f"phase285-integrity: mutation reached checker execution: {name}")
        killed += 1
        print(f"phase285_witness_integrity_self_test_red mutation={name}")
    if killed != 14:
        raise SystemExit("phase285-integrity: mutation cardinality differs")
    print("phase285_witness_integrity_self_test mutations=14 positive_checker_executions=1 passed=1")
PY
}

if [ "${1:-}" = --integrity-self-test ]; then
  [ "$#" -eq 1 ] || { echo "usage: $0 --integrity-self-test|<checker arguments>" >&2; exit 2; }
  run_integrity_self_test
  exit 0
fi

write_execution_sentinel
echo "phase285_witness_integrity scope=local_frozen_tree_root_integrator_integrity coordinated_repo_mutation=not_covered external_app_enforcement=deferred"
exec bash "$checker" "$@"
