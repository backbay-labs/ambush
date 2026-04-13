#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

python3 - <<'PY'
from __future__ import annotations

import pathlib
import re
import sys

ALLOWED_MARKER = "SAFETY: runtime panic contract exception"
PANIC_CALL = re.compile(r"\.(unwrap|expect)\s*\(")
CFG_TEST_ATTR = re.compile(r"#\s*\[\s*cfg\s*\(\s*test\s*\)\s*\]", re.S)


def blank(chars: list[str], start: int, end: int) -> None:
    for index in range(start, end):
        if chars[index] != "\n":
            chars[index] = " "


def consume_line_comment(text: str, start: int) -> int:
    index = start + 2
    while index < len(text) and text[index] != "\n":
        index += 1
    return index


def consume_block_comment(text: str, start: int) -> int:
    depth = 1
    index = start + 2
    while index < len(text) and depth > 0:
        if text.startswith("/*", index):
            depth += 1
            index += 2
        elif text.startswith("*/", index):
            depth -= 1
            index += 2
        else:
            index += 1
    return index


def consume_quoted(text: str, start: int, quote: str) -> int:
    index = start + 1
    escaped = False
    while index < len(text):
        char = text[index]
        if escaped:
            escaped = False
        elif char == "\\":
            escaped = True
        elif char == quote:
            return index + 1
        index += 1
    return index


def consume_char_literal(text: str, start: int) -> int | None:
    if text[start] != "'":
        return None

    index = start + 1
    if index >= len(text) or text[index] in {"\n", "\r", "'"}:
        return None

    escaped = False
    while index < len(text):
        char = text[index]
        if escaped:
            escaped = False
        elif char == "\\":
            escaped = True
        elif char == "'":
            return index + 1
        elif char in {"\n", "\r"}:
            return None
        index += 1

    return None


def consume_raw_string(text: str, start: int) -> int | None:
    prefix_len = 0
    if text.startswith("br", start):
        prefix_len = 2
    elif text.startswith("r", start):
        prefix_len = 1
    else:
        return None

    index = start + prefix_len
    while index < len(text) and text[index] == "#":
        index += 1
    if index >= len(text) or text[index] != '"':
        return None

    hashes = index - (start + prefix_len)
    terminator = '"' + ("#" * hashes)
    end = text.find(terminator, index + 1)
    if end == -1:
        return len(text)
    return end + len(terminator)


def skip_whitespace_and_comments(text: str, start: int) -> int:
    index = start
    while index < len(text):
        if text[index].isspace():
            index += 1
        elif text.startswith("//", index):
            index = consume_line_comment(text, index)
        elif text.startswith("/*", index):
            index = consume_block_comment(text, index)
        else:
            return index
    return index


def skip_cfg_test_item(text: str, start: int) -> int:
    index = skip_whitespace_and_comments(text, start)
    paren_depth = 0
    bracket_depth = 0
    angle_depth = 0
    brace_depth = 0
    saw_body = False

    while index < len(text):
        raw_end = consume_raw_string(text, index)
        if raw_end is not None:
            index = raw_end
            continue
        if text.startswith("//", index):
            index = consume_line_comment(text, index)
            continue
        if text.startswith("/*", index):
            index = consume_block_comment(text, index)
            continue
        if text.startswith('b"', index):
            index = consume_quoted(text, index + 1, '"')
            continue
        if text.startswith("b'", index):
            char_end = consume_char_literal(text, index + 1)
            if char_end is not None:
                index = char_end
                continue
        if text[index] == '"':
            index = consume_quoted(text, index, '"')
            continue
        char_end = consume_char_literal(text, index)
        if char_end is not None:
            index = char_end
            continue

        char = text[index]
        if not saw_body:
            if char == "(":
                paren_depth += 1
            elif char == ")" and paren_depth > 0:
                paren_depth -= 1
            elif char == "[":
                bracket_depth += 1
            elif char == "]" and bracket_depth > 0:
                bracket_depth -= 1
            elif char == "<":
                angle_depth += 1
            elif char == ">" and angle_depth > 0:
                angle_depth -= 1
            elif char == "{" and paren_depth == 0 and bracket_depth == 0 and angle_depth == 0:
                saw_body = True
                brace_depth = 1
            elif (
                char in ";,"
                and paren_depth == 0
                and bracket_depth == 0
                and angle_depth == 0
            ):
                return index + 1
            index += 1
            continue

        if char == "{":
            brace_depth += 1
        elif char == "}":
            brace_depth -= 1
            index += 1
            if brace_depth == 0:
                return index
            continue
        index += 1

    return index


def sanitize_runtime_source(text: str) -> str:
    chars = list(text)
    index = 0
    while index < len(text):
        cfg_match = CFG_TEST_ATTR.match(text, index)
        if cfg_match:
            blank(chars, index, cfg_match.end())
            item_end = skip_cfg_test_item(text, cfg_match.end())
            blank(chars, cfg_match.end(), item_end)
            index = item_end
            continue

        raw_end = consume_raw_string(text, index)
        if raw_end is not None:
            blank(chars, index, raw_end)
            index = raw_end
            continue
        if text.startswith("//", index):
            end = consume_line_comment(text, index)
            blank(chars, index, end)
            index = end
            continue
        if text.startswith("/*", index):
            end = consume_block_comment(text, index)
            blank(chars, index, end)
            index = end
            continue
        if text.startswith('b"', index):
            end = consume_quoted(text, index + 1, '"')
            blank(chars, index, end)
            index = end
            continue
        if text.startswith("b'", index):
            end = consume_char_literal(text, index + 1)
            if end is not None:
                blank(chars, index, end)
                index = end
                continue
        if text[index] == '"':
            end = consume_quoted(text, index, '"')
            blank(chars, index, end)
            index = end
            continue
        end = consume_char_literal(text, index)
        if end is not None:
            blank(chars, index, end)
            index = end
            continue

        index += 1

    return "".join(chars)


def has_allowed_marker(lines: list[str], line_number: int) -> bool:
    for index in range(line_number - 1, max(-1, line_number - 4), -1):
        stripped = lines[index].strip()
        if not stripped:
            continue
        return stripped.startswith(f"// {ALLOWED_MARKER}")
    return False


def line_number_for_offset(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


runtime_src = pathlib.Path("crates/swarm-runtime/src")
files = sorted(
    path
    for path in runtime_src.rglob("*")
    if path.is_file() and path.suffix in {".rs", ".inc"} and path.name != "tests.rs"
)

violations: list[tuple[str, int, str]] = []
allowed: list[tuple[str, int, str]] = []

for path in files:
    source = path.read_text(encoding="utf-8")
    sanitized = sanitize_runtime_source(source)
    lines = source.splitlines()
    for match in PANIC_CALL.finditer(sanitized):
        line_number = line_number_for_offset(source, match.start())
        call = f".{match.group(1)}("
        record = (path.as_posix(), line_number, call)
        if has_allowed_marker(lines, line_number):
            allowed.append(record)
        else:
            violations.append(record)

if violations:
    print("runtime panic contract violation(s) detected:", file=sys.stderr)
    for path, line_number, call in violations:
        print(f"- {path}:{line_number} uses {call}", file=sys.stderr)
    print(
        f"Allowed exception marker: // {ALLOWED_MARKER}",
        file=sys.stderr,
    )
    sys.exit(1)

if allowed:
    print(
        f"runtime panic contract OK: 0 live violations, {len(allowed)} explicit exception(s)"
    )
else:
    print("runtime panic contract OK: 0 live unwrap()/expect() sites in swarm-runtime")
PY
