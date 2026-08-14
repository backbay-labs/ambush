"""Rust source-inventory and lexical helpers for the phase-285 assurance gates.

Cargo/rustc dep-info is authoritative for the real tree's compiled source files.
Within those files this deliberately small parser removes comments and literals
without changing byte offsets, resolves the crate module graph, and identifies
concrete function bodies and executable guard adjacency. Raw grep cannot make
those distinctions and therefore cannot police evidence.
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
import json
import pathlib
import re
import shlex
import subprocess


@dataclass(frozen=True)
class LineComment:
    start: int
    end: int
    text: str


@dataclass(frozen=True)
class FunctionSpan:
    name: str
    type_name: str | None
    declaration_start: int
    body_start: int
    body_end: int


def _blank(chars: list[str], start: int, end: int) -> None:
    for index in range(start, end):
        if chars[index] not in "\r\n":
            chars[index] = " "


def sanitize_rust(text: str) -> tuple[str, list[LineComment]]:
    """Blank comments and string/character literals while preserving offsets."""

    chars = list(text)
    comments: list[LineComment] = []
    index = 0
    length = len(text)
    while index < length:
        if text.startswith("//", index):
            end = text.find("\n", index + 2)
            if end < 0:
                end = length
            comments.append(LineComment(index, end, text[index + 2 : end]))
            _blank(chars, index, end)
            index = end
            continue

        if text.startswith("/*", index):
            depth = 1
            end = index + 2
            while end < length and depth:
                if text.startswith("/*", end):
                    depth += 1
                    end += 2
                elif text.startswith("*/", end):
                    depth -= 1
                    end += 2
                else:
                    end += 1
            _blank(chars, index, end)
            index = end
            continue

        raw = re.match(r"(?:br|rb|r)(?P<hashes>#{0,255})\"", text[index:])
        if raw:
            terminator = '"' + raw.group("hashes")
            content_start = index + raw.end()
            found = text.find(terminator, content_start)
            end = length if found < 0 else found + len(terminator)
            _blank(chars, index, end)
            index = end
            continue

        prefix = 1 if text.startswith('b"', index) else 0
        if index + prefix < length and text[index + prefix] == '"':
            end = index + prefix + 1
            escaped = False
            while end < length:
                char = text[end]
                end += 1
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == '"':
                    break
            _blank(chars, index, end)
            index = end
            continue

        # Do not erase lifetimes.  A Rust character literal has either one
        # codepoint followed by a quote or an escape followed by a quote.
        if text[index] == "'":
            if index + 2 < length and text[index + 2] == "'":
                end = index + 3
                _blank(chars, index, end)
                index = end
                continue
            if index + 3 < length and text[index + 1] == "\\":
                end_quote = text.find("'", index + 2)
                if end_quote >= 0:
                    end = end_quote + 1
                    _blank(chars, index, end)
                    index = end
                    continue

        index += 1

    return "".join(chars), comments


def matching_brace(text: str, opening: int) -> int | None:
    depth = 0
    for index in range(opening, len(text)):
        if text[index] == "{":
            depth += 1
        elif text[index] == "}":
            depth -= 1
            if depth == 0:
                return index
    return None


def _cfg_test_ranges(clean: str) -> list[tuple[int, int]]:
    ranges: list[tuple[int, int]] = []
    pattern = re.compile(r"#\s*\[\s*cfg\s*\(\s*test\s*\)\s*\]")
    for match in pattern.finditer(clean):
        cursor = match.end()
        # Permit additional attributes between cfg(test) and its item.
        while True:
            attribute = re.match(r"\s*#\s*\[[^\]]*\]", clean[cursor:])
            if not attribute:
                break
            cursor += attribute.end()
        opening = clean.find("{", cursor)
        semicolon = clean.find(";", cursor)
        if semicolon >= 0 and (opening < 0 or semicolon < opening):
            ranges.append((match.start(), semicolon + 1))
            continue
        if opening >= 0:
            closing = matching_brace(clean, opening)
            if closing is not None:
                ranges.append((match.start(), closing + 1))
    return ranges


def production_sanitized(text: str) -> tuple[str, list[LineComment]]:
    clean, comments = sanitize_rust(text)
    chars = list(clean)
    excluded = _cfg_test_ranges(clean)
    for start, end in excluded:
        _blank(chars, start, end)
    kept_comments = [
        comment
        for comment in comments
        if not any(start <= comment.start < end for start, end in excluded)
    ]
    return "".join(chars), kept_comments


def _impl_type(header: str) -> str | None:
    tokens = re.findall(r"[A-Za-z_][A-Za-z0-9_]*|[<>]", header)
    if not tokens or tokens[0] != "impl":
        return None
    cursor = 1
    if cursor < len(tokens) and tokens[cursor] == "<":
        depth = 1
        cursor += 1
        while cursor < len(tokens) and depth:
            depth += tokens[cursor] == "<"
            depth -= tokens[cursor] == ">"
            cursor += 1
    remainder = tokens[cursor:]
    if "for" in remainder:
        cursor = remainder.index("for") + 1
        remainder = remainder[cursor:]
    for token in remainder:
        if token[:1].isupper():
            return token
    return None


def impl_spans(clean: str) -> list[tuple[int, int, str | None]]:
    spans: list[tuple[int, int, str | None]] = []
    for match in re.finditer(r"\bimpl\b", clean):
        opening = clean.find("{", match.end())
        if opening < 0:
            continue
        closing = matching_brace(clean, opening)
        if closing is None:
            continue
        spans.append((opening, closing, _impl_type(clean[match.start() : opening])))
    return spans


def function_spans(clean: str) -> list[FunctionSpan]:
    implementations = impl_spans(clean)
    spans: list[FunctionSpan] = []
    for match in re.finditer(r"\bfn\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*(?:<[^{};]*>)?\s*\(", clean):
        opening = clean.find("{", match.end())
        semicolon = clean.find(";", match.end())
        if opening < 0 or (semicolon >= 0 and semicolon < opening):
            continue
        closing = matching_brace(clean, opening)
        if closing is None:
            continue
        enclosing = [span for span in implementations if span[0] < match.start() < span[1]]
        type_name = min(enclosing, key=lambda span: span[1] - span[0])[2] if enclosing else None
        line_start = clean.rfind("\n", 0, match.start()) + 1
        spans.append(
            FunctionSpan(
                match.group("name"),
                type_name,
                line_start,
                opening,
                closing,
            )
        )
    return spans


def find_function(clean: str, name: str, type_name: str | None) -> FunctionSpan | None:
    candidates = [span for span in function_spans(clean) if span.name == name]
    if type_name is None:
        candidates = [span for span in candidates if span.type_name is None]
    else:
        candidates = [span for span in candidates if span.type_name == type_name]
    return candidates[0] if len(candidates) == 1 else None


@dataclass
class ModuleNode:
    path: pathlib.Path
    module: tuple[str, ...]
    start: int
    end: int
    child_base: pathlib.Path
    path_base: pathlib.Path
    children: list["ModuleNode"]


@lru_cache(maxsize=None)
def _source(path: str) -> tuple[str, str]:
    raw = pathlib.Path(path).read_text(encoding="utf-8", errors="replace")
    clean, _ = production_sanitized(raw)
    return raw, clean


@lru_cache(maxsize=None)
def _file_function_spans(path: str) -> tuple[FunctionSpan, ...]:
    return tuple(function_spans(_source(path)[1]))


def _depth_at(clean: str, start: int, position: int) -> int:
    return clean.count("{", start, position) - clean.count("}", start, position)


@lru_cache(maxsize=1)
def _active_rustc_cfg() -> frozenset[str]:
    result = subprocess.run(
        ["rustc", "--print", "cfg"],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if result.returncode:
        raise RuntimeError(f"rustc --print cfg failed: {result.stderr}")
    return frozenset(re.sub(r"\s+", "", line) for line in result.stdout.splitlines())


def _split_cfg_arguments(value: str) -> list[str]:
    parts: list[str] = []
    depth = 0
    start = 0
    for index, char in enumerate(value):
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
        elif char == "," and depth == 0:
            parts.append(value[start:index])
            start = index + 1
    parts.append(value[start:])
    return [part for part in parts if part]


def _cfg_expression_enabled(expression: str) -> bool:
    expression = re.sub(r"\s+", "", expression)
    for operator in ("all", "any", "not"):
        prefix = operator + "("
        if expression.startswith(prefix) and expression.endswith(")"):
            values = _split_cfg_arguments(expression[len(prefix):-1])
            if operator == "all":
                return all(_cfg_expression_enabled(value) for value in values)
            if operator == "any":
                return any(_cfg_expression_enabled(value) for value in values)
            return len(values) == 1 and not _cfg_expression_enabled(values[0])
    return expression in _active_rustc_cfg()


def cfg_attributes_enabled(attributes: set[str]) -> bool:
    for attribute in attributes:
        if attribute.startswith("cfg(") and attribute.endswith(")"):
            if not _cfg_expression_enabled(attribute[4:-1]):
                return False
        elif attribute.startswith("cfg_attr(") and attribute.endswith(")"):
            parts = _split_cfg_arguments(attribute[9:-1])
            if not parts:
                return False
            condition = _cfg_expression_enabled(parts[0])
            if condition:
                for nested in parts[1:]:
                    if nested.startswith("cfg(") and not cfg_attributes_enabled({nested}):
                        return False
    return True


def _module_children(node: ModuleNode) -> list[ModuleNode]:
    raw, clean = _source(str(node.path))
    pattern = re.compile(
        r"(?P<attrs>(?:#\s*\[[^\]]*\]\s*)*)"
        r"(?:pub(?:\s*\([^)]*\))?\s+)?mod\s+"
        r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*(?P<kind>[;{])"
    )
    children: list[ModuleNode] = []
    for match in pattern.finditer(clean, node.start, node.end):
        if _depth_at(clean, node.start, match.start()) != 0:
            continue
        # A conditionally compiled declaration is not an unconditional member
        # of the production module graph.  Do not try to guess a target's cfg
        # environment: fail closed by making paths through it unresolvable.
        raw_attrs = raw[match.start("attrs") : match.end("attrs")]
        attributes = {
            re.sub(r"\s+", "", attribute)
            for attribute in re.findall(r"#\s*\[\s*([^\]]+)\]", raw_attrs)
        }
        if not cfg_attributes_enabled(attributes):
            continue
        name = match.group("name")
        if match.group("kind") == "{":
            opening = clean.find("{", match.start(), match.end() + 1)
            closing = matching_brace(clean, opening)
            if closing is None or closing > node.end:
                continue
            child = ModuleNode(
                node.path,
                node.module + (name,),
                opening + 1,
                closing,
                node.child_base / name,
                node.child_base / name,
                [],
            )
        else:
            path_attr = re.search(r"\bpath\s*=\s*\"([^\"]+)\"", raw_attrs)
            candidates = (
                [node.path_base / path_attr.group(1)]
                if path_attr
                else [node.child_base / f"{name}.rs", node.child_base / name / "mod.rs"]
            )
            target = next((candidate for candidate in candidates if candidate.is_file()), None)
            if target is None:
                continue
            _, target_clean = _source(str(target))
            child_base = target.parent if target.name == "mod.rs" else node.child_base / name
            child = ModuleNode(
                target,
                node.module + (name,),
                0,
                len(target_clean),
                child_base,
                target.parent,
                [],
            )
        child.children = _module_children(child)
        children.append(child)
    return children


@lru_cache(maxsize=None)
def _crate_graph(crate_src: str) -> ModuleNode | None:
    source_dir = pathlib.Path(crate_src)
    root_file = source_dir / "lib.rs"
    if not root_file.is_file():
        root_file = source_dir / "main.rs"
    if not root_file.is_file():
        return None
    _, clean = _source(str(root_file))
    root = ModuleNode(root_file, (), 0, len(clean), source_dir, source_dir, [])
    root.children = _module_children(root)
    return root


def _walk_modules(node: ModuleNode):
    yield node
    for child in node.children:
        yield from _walk_modules(child)


@lru_cache(maxsize=None)
def _rustc_source_inventory(
    repo_root: str, crate_names: tuple[str, ...]
) -> frozenset[pathlib.Path] | None:
    """Return rustc's actual default-build source inventory from dep-info.

    Fixtures without a Cargo workspace use the module-graph fallback. A real
    workspace never silently falls back: failure to obtain dep-info is a gate
    failure, because a guessed inventory is exactly the evasion this check is
    meant to prevent.
    """

    root = pathlib.Path(repo_root)
    if not (root / "Cargo.toml").is_file():
        return None
    command = ["cargo", "check", "--lib"]
    for crate in crate_names:
        command.extend(("-p", crate))
    command.append("--message-format=json")
    result = subprocess.run(
        command,
        cwd=root,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if result.returncode:
        raise RuntimeError(f"cargo dep-info inventory failed: {result.stderr[-4000:]}")

    wanted_targets = {crate.replace("-", "_") for crate in crate_names}
    dep_files: dict[str, pathlib.Path] = {}
    for line in result.stdout.splitlines():
        if not line.startswith("{"):
            continue
        message = json.loads(line)
        target = message.get("target", {})
        name = target.get("name")
        if message.get("reason") != "compiler-artifact" or name not in wanted_targets:
            continue
        if "lib" not in target.get("kind", []):
            continue
        artifact = next(
            (pathlib.Path(value) for value in message.get("filenames", []) if value.endswith((".rmeta", ".rlib"))),
            None,
        )
        if artifact is not None:
            dep_files[name] = artifact.with_name(artifact.stem.removeprefix("lib") + ".d")
    missing = wanted_targets - set(dep_files)
    if missing:
        raise RuntimeError(f"cargo emitted no lib dep-info artifact for {sorted(missing)}")

    sources: set[pathlib.Path] = set()
    for dep_file in dep_files.values():
        if not dep_file.is_file():
            raise RuntimeError(f"rustc dep-info file is absent: {dep_file}")
        dep_text = dep_file.read_text(encoding="utf-8", errors="replace").replace("\\\n", " ")
        first_rule = dep_text.splitlines()[0]
        _, separator, dependencies = first_rule.partition(": ")
        if not separator:
            raise RuntimeError(f"rustc dep-info has no dependency rule: {dep_file}")
        for value in shlex.split(dependencies):
            candidate = pathlib.Path(value)
            if not candidate.is_absolute():
                candidate = root / candidate
            candidate = candidate.resolve()
            if candidate.suffix == ".rs" and candidate.is_file():
                sources.add(candidate)
    return frozenset(sources)


def reachable_rust_files(
    root: pathlib.Path, crate_names: set[str] | None = None
) -> set[pathlib.Path]:
    if crate_names:
        inventory = _rustc_source_inventory(
            str(root.resolve()), tuple(sorted(crate_names))
        )
        if inventory is not None:
            crate_roots = [(root / "crates" / crate / "src").resolve() for crate in crate_names]
            return {
                path
                for path in inventory
                if any(path.is_relative_to(crate_root) for crate_root in crate_roots)
            }
    files: set[pathlib.Path] = set()
    for crate_src in sorted((root / "crates").glob("*/src")):
        if crate_names is not None and crate_src.parent.name not in crate_names:
            continue
        graph = _crate_graph(str(crate_src))
        if graph is not None:
            files.update(node.path for node in _walk_modules(graph))
    return files


def resolve_function(root: pathlib.Path, path_str: str) -> tuple[pathlib.Path, FunctionSpan] | str:
    """Resolve an exact crate::module::[Type::]function path or return a reason."""

    segments = path_str.split("::")
    if len(segments) < 2:
        return f"`{path_str}` is not a crate function path"
    crate_dir = root / "crates" / segments[0].replace("_", "-") / "src"
    if not crate_dir.is_dir():
        return f"crate `{segments[0]}` has no source directory"

    graph = _crate_graph(str(crate_dir))
    if graph is None:
        return f"crate `{segments[0]}` has no lib.rs or main.rs module root"
    rest = segments[1:]
    nodes = {node.module: node for node in _walk_modules(graph)}
    cursor = 0
    while cursor < len(rest) and tuple(rest[: cursor + 1]) in nodes:
        cursor += 1
    node = nodes.get(tuple(rest[:cursor]))
    if node is None:
        return f"`{path_str}` names a module not reachable from the crate root"
    remaining = rest[cursor:]
    if len(remaining) == 1:
        type_name, fn_name = None, remaining[0]
    elif len(remaining) == 2 and remaining[0][:1].isupper():
        type_name, fn_name = remaining
    else:
        return f"`{path_str}` does not end in function or Type::function"

    raw, clean = _source(str(node.path))
    nested_ranges = [
        (child.start, child.end)
        for child in node.children
        if child.path == node.path
    ]
    candidates = [
        span
        for span in _file_function_spans(str(node.path))
        if node.start <= span.declaration_start < node.end
        and not any(start <= span.declaration_start < end for start, end in nested_ranges)
        and span.name == fn_name
        and span.type_name == type_name
        and cfg_attributes_enabled(function_attributes(raw, span))
    ]
    if len(candidates) != 1:
        target = f"{type_name}::{fn_name}" if type_name else fn_name
        return f"`{node.path.relative_to(root)}` declares no unique reachable production `{target}` body"
    return node.path, candidates[0]


def test_function(clean: str, name: str) -> FunctionSpan | None:
    span = find_function(clean, name, None)
    if span is None:
        return None
    lines = clean[: span.declaration_start].splitlines()
    adjacent: list[str] = []
    for line in reversed(lines):
        stripped = line.strip()
        if not stripped and not adjacent:
            continue
        if re.fullmatch(r"#\s*\[[^\]]+\]", stripped):
            adjacent.append(stripped)
            continue
        break
    attributes = re.findall(r"#\s*\[\s*([^\]]+)\]", "\n".join(adjacent))
    normalized = {re.sub(r"\s+", "", attribute) for attribute in attributes}
    if not any(value == "test" or value.startswith("tokio::test") for value in normalized):
        return None
    return span


def function_attributes(clean: str, span: FunctionSpan) -> set[str]:
    lines = clean[: span.declaration_start].splitlines()
    adjacent: list[str] = []
    for line in reversed(lines):
        stripped = line.strip()
        if not stripped and not adjacent:
            continue
        if re.fullmatch(r"#\s*\[[^\]]+\]", stripped):
            adjacent.append(stripped)
            continue
        break
    return {
        re.sub(r"\s+", "", attribute)
        for attribute in re.findall(r"#\s*\[\s*([^\]]+)\]", "\n".join(adjacent))
    }


def function_has_conditional_owner(clean: str, span: FunctionSpan) -> bool:
    """Return true when a function or any enclosing inline item has cfg state.

    Cargo discovery is authoritative for the real targets. This structural
    check makes module-level `cfg` disabling visible in the adversarial fixture
    too, instead of looking only at attributes immediately above the function.
    """

    pattern = re.compile(r"#\s*\[\s*cfg(?:_attr)?\b[^\]]*\]")
    for match in pattern.finditer(clean, 0, span.declaration_start):
        cursor = match.end()
        while True:
            attribute = re.match(r"\s*#\s*\[[^\]]*\]", clean[cursor:])
            if not attribute:
                break
            cursor += attribute.end()
        opening = clean.find("{", cursor)
        semicolon = clean.find(";", cursor)
        if semicolon >= 0 and (opening < 0 or semicolon < opening):
            end = semicolon + 1
        elif opening >= 0:
            closing = matching_brace(clean, opening)
            end = len(clean) if closing is None else closing + 1
        else:
            continue
        if match.start() <= span.declaration_start < end:
            return True
    return False


def enum_variant_defined(
    clean: str,
    evidence: str,
    excluded: tuple[int, int] | None = None,
) -> bool:
    """Resolve exact `Enum::Variant` evidence outside the attributed test."""

    match = re.fullmatch(
        r"(?P<enum>[A-Za-z_][A-Za-z0-9_]*)::(?P<variant>[A-Za-z_][A-Za-z0-9_]*)",
        evidence,
    )
    if match is None:
        return False
    chars = list(clean)
    if excluded is not None:
        _blank(chars, excluded[0], excluded[1])
    outside = "".join(chars)
    declarations = list(
        re.finditer(r"\benum\s+" + re.escape(match.group("enum")) + r"\s*\{", outside)
    )
    if len(declarations) != 1:
        return False
    opening = outside.find("{", declarations[0].start())
    closing = matching_brace(outside, opening)
    if closing is None:
        return False
    body = outside[opening + 1 : closing]
    return bool(
        re.search(
            r"(?m)^\s*" + re.escape(match.group("variant")) + r"\s*(?:[,({=])",
            body,
        )
    )


def next_code_line(clean: str, position: int) -> tuple[int, str] | None:
    cursor = clean.find("\n", position)
    cursor = len(clean) if cursor < 0 else cursor + 1
    while cursor < len(clean):
        end = clean.find("\n", cursor)
        end = len(clean) if end < 0 else end
        line = clean[cursor:end]
        if line.strip():
            statement = line.strip()
            if statement.startswith("let ") and ";" not in statement and "else" not in statement:
                continuation = end + 1
                while continuation < len(clean):
                    next_end = clean.find("\n", continuation)
                    next_end = len(clean) if next_end < 0 else next_end
                    fragment = clean[continuation:next_end].strip()
                    if fragment:
                        statement += " " + fragment
                    if ";" in fragment or "else" in fragment:
                        break
                    continuation = next_end + 1
            return cursor, statement
        cursor = end + 1
    return None


def looks_like_executable_guard(line: str) -> bool:
    """Recognize the decision forms to which an INVARIANT marker may attach."""

    stripped = line.lstrip("}").strip()
    if re.match(r"(?:else\s+)?if\b|else\b|match\b", stripped):
        return True
    if "=>" in stripped:
        return True
    if re.match(r"let\b", stripped) and ("else" in stripped or "?" in stripped):
        return True
    if re.match(r"(?:return\s+)?(?:Err|Ok)\s*\(", stripped):
        return True
    # A Result-propagating call is an executable refusal decision even though
    # Rust spells it with `?` rather than an `if`.
    return "?" in stripped
