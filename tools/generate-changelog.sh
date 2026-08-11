#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

usage() {
  cat <<'EOF' >&2
usage: tools/generate-changelog.sh --tag <version> [--to <ref>] [--from <ref>] [--output <path>]
EOF
  exit 64
}

TAG=""
TO_REF=""
FROM_REF=""
OUTPUT=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --tag)
      TAG="${2:-}"
      shift 2
      ;;
    --to)
      TO_REF="${2:-}"
      shift 2
      ;;
    --from)
      FROM_REF="${2:-}"
      shift 2
      ;;
    --output)
      OUTPUT="${2:-}"
      shift 2
      ;;
    *)
      usage
      ;;
  esac
done

if [[ -z "$TAG" ]]; then
  usage
fi

if [[ -z "$TO_REF" ]]; then
  TO_REF="$TAG"
fi

if [[ -z "$FROM_REF" ]]; then
  FROM_REF="$(python3 - "$TAG" <<'PY'
import subprocess
import sys

target = sys.argv[1]
tags = subprocess.check_output(
    ["git", "tag", "--list", "v*", "--sort=version:refname"],
    text=True,
).splitlines()
previous = ""
for tag in tags:
    if tag == target:
        break
    previous = tag
print(previous)
PY
)"
fi

if [[ -n "$OUTPUT" ]]; then
  mkdir -p "$(dirname "$OUTPUT")"
fi

python3 - "$TAG" "$TO_REF" "$FROM_REF" "$OUTPUT" <<'PY'
from __future__ import annotations

import datetime as dt
import os
import re
import subprocess
import sys
from collections import OrderedDict

tag, to_ref, from_ref, output = sys.argv[1:5]

commit_format = "%H%x1f%s%x1f%b%x1e"
revision_range = [to_ref] if not from_ref else [f"{from_ref}..{to_ref}"]
raw = subprocess.check_output(
    ["git", "log", "--reverse", f"--format={commit_format}", *revision_range],
    text=True,
)

remote = ""
for candidate in (
    subprocess.run(["git", "config", "--get", "remote.origin.url"], text=True, capture_output=True).stdout.strip(),
):
    if candidate:
        remote = candidate
        break

if remote.startswith("git@github.com:"):
    remote = "https://github.com/" + remote[len("git@github.com:") :]
if remote.endswith(".git"):
    remote = remote[:-4]

commit_re = re.compile(
    r"^(?P<type>[a-z]+)(?:\((?P<scope>[^)]+)\))?(?P<breaking>!)?: (?P<description>.+)$"
)

sections = OrderedDict(
    [
        ("breaking", "Breaking Changes"),
        ("feat", "Features"),
        ("fix", "Fixes"),
        ("perf", "Performance"),
        ("refactor", "Refactors"),
        ("build", "Build"),
        ("ci", "CI"),
        ("docs", "Documentation"),
        ("test", "Tests"),
        ("chore", "Chore"),
        ("revert", "Reverts"),
        ("other", "Other Changes"),
    ]
)
grouped: dict[str, list[str]] = {key: [] for key in sections}

def commit_link(commit_sha: str) -> str:
    short = commit_sha[:7]
    if remote:
        return f"[`{short}`]({remote}/commit/{commit_sha})"
    return f"`{short}`"

for entry in raw.split("\x1e"):
    entry = entry.rstrip("\n")
    if not entry:
        continue
    parts = entry.split("\x1f", 2)
    while len(parts) < 3:
        parts.append("")
    commit_sha, subject, body = parts
    subject = subject.strip()
    body = body.strip()
    match = commit_re.match(subject)

    section_key = "other"
    scope = None
    description = subject
    breaking = "BREAKING CHANGE:" in body

    if match:
        section_key = match.group("type")
        scope = match.group("scope")
        description = match.group("description").strip()
        if match.group("breaking"):
            breaking = True

    if section_key not in grouped:
        section_key = "other"

    rendered = description
    if scope:
        rendered = f"**{scope}:** {rendered}"
    rendered = f"- {rendered} ({commit_link(commit_sha)})"

    if breaking:
        grouped["breaking"].append(rendered)
    grouped[section_key].append(rendered)

compare_line = ""
if remote and from_ref:
    compare_line = f"_Compare: [{from_ref}...{tag}]({remote}/compare/{from_ref}...{tag})_\n\n"
elif from_ref:
    compare_line = f"_Compare: `{from_ref}...{tag}`_\n\n"

parts = [
    "# Changelog\n\n",
    f"## {tag} - {dt.date.today().isoformat()}\n\n",
    compare_line,
]

non_empty = False
for key, title in sections.items():
    items = grouped[key]
    if not items:
        continue
    non_empty = True
    parts.append(f"### {title}\n")
    parts.extend(f"{item}\n" for item in items)
    parts.append("\n")

if not non_empty:
    parts.append("- No commits found in the selected release range.\n")

rendered = "".join(parts)
if output:
    with open(output, "w", encoding="utf-8") as handle:
        handle.write(rendered)
else:
    print(rendered, end="")
PY
