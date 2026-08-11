#!/usr/bin/env bash
# Fails if any TRACKED file looks like private key material.
#
# Why this exists: rulesets/data/agent-keys/sphinx-primary.ed25519 -- a live
# 32-byte Ed25519 seed that FileAgentKeyStore::load_or_create loads as the
# Sphinx primary identity -- was tracked from commit 69814a4 until the
# repository was made public. .gitignore cannot fix this class of defect on its
# own, because ignore rules do not apply to files that are already tracked. Only
# a positive assertion over `git ls-files` catches a key that is already in.
#
# Detects, over tracked files only:
#   1. key-ish extensions (.ed25519 .pem .key .p12 .pfx .jks .keystore)
#   2. any path inside an agent-keys/ directory
#   3. PEM / OpenSSH / PuTTY private-key headers in file content
#   4. small high-entropy BINARY blobs (32 or 64 bytes) -- the shape that hid the
#      Sphinx key, which has no extension-independent signature at all
#
# Does NOT detect: secrets pasted into source as string literals (clippy and
# review cover those), anything only present in git HISTORY rather than HEAD
# (removing a key from HEAD does not un-publish it -- rotate instead), or
# credentials in files this repo does not track.
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

python3 - "$@" <<'PY'
import math, pathlib, subprocess, sys

KEY_EXT = {".ed25519", ".pem", ".key", ".p12", ".pfx", ".jks", ".keystore"}
HEADERS = (b"-----BEGIN", b"ssh-rsa ", b"ssh-ed25519 ", b"PuTTY-User-Key-File")
# Bytes that are plausibly a raw seed / expanded key.
RAW_KEY_SIZES = {32, 64}

def entropy(b: bytes) -> float:
    if not b:
        return 0.0
    counts = [0] * 256
    for byte in b:
        counts[byte] += 1
    n = len(b)
    return -sum((c / n) * math.log2(c / n) for c in counts if c)

tracked = subprocess.run(
    ["git", "ls-files", "-z"], capture_output=True, check=True
).stdout.split(b"\0")

violations = []
for raw in tracked:
    if not raw:
        continue
    rel = raw.decode("utf-8", "surrogateescape")
    path = pathlib.Path(rel)
    if not path.is_file():
        continue

    if path.suffix.lower() in KEY_EXT:
        violations.append((rel, f"key-material extension '{path.suffix}'"))
        continue
    if any(part == "agent-keys" for part in path.parts):
        violations.append((rel, "inside an agent-keys/ directory"))
        continue

    try:
        data = path.read_bytes()
    except OSError:
        continue

    head = data[:200]
    if any(h in head for h in HEADERS):
        violations.append((rel, "contains a private-key header"))
        continue

    if len(data) in RAW_KEY_SIZES and b"\0" in data or (
        len(data) in RAW_KEY_SIZES and entropy(data) > 4.5
    ):
        try:
            data.decode("utf-8")
            is_text = True
        except UnicodeDecodeError:
            is_text = False
        if not is_text:
            violations.append(
                (rel, f"{len(data)}-byte high-entropy binary blob "
                      f"(entropy {entropy(data):.2f}) -- looks like a raw key seed")
            )

if violations:
    print("committed key material detected:", file=sys.stderr)
    for rel, why in violations:
        print(f"- {rel}: {why}", file=sys.stderr)
    print(
        "\nRemove it (git rm --cached), add it to .gitignore, and ROTATE the "
        "credential: anything that was pushed must be assumed compromised.",
        file=sys.stderr,
    )
    sys.exit(1)

print(f"no committed key material: scanned {sum(1 for r in tracked if r)} tracked file(s)")
PY
