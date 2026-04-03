"""Hellcat prompt template loader.

Resolves ``@include(...)`` directives and substitutes ``{{VAR}}`` placeholders
from an :class:`AttackManifest`.
"""

from __future__ import annotations

import re
from pathlib import Path

from hellcat.offensive.operator_base import AttackManifest

_INCLUDE_RE = re.compile(r"@include\(([^)]+)\)")
_VAR_RE = re.compile(r"\{\{(\w+)\}\}")

_MAX_INCLUDE_DEPTH = 5


def load_prompt(
    template_path: str,
    repo_root: Path,
    variables: dict[str, str],
) -> str:
    """Load a Hellcat prompt template, resolving includes and variables.

    Args:
        template_path: Relative path from *repo_root* (e.g.
            ``prompts/vuln-injection.txt``).
        repo_root: Absolute path to the Hellcat repo root containing the
            ``prompts/`` directory.
        variables: ``{{KEY}}`` → value mapping to substitute.

    Returns:
        Fully-resolved prompt string.
    """
    abs_path = repo_root / template_path
    text = _resolve_includes(abs_path, repo_root, depth=0)
    text = _substitute_variables(text, variables)
    return text


def _resolve_includes(path: Path, repo_root: Path, depth: int) -> str:
    """Recursively resolve ``@include(relative/path.txt)`` directives."""
    if depth > _MAX_INCLUDE_DEPTH:
        return f"[ERROR: max include depth ({_MAX_INCLUDE_DEPTH}) exceeded for {path}]"

    if not path.exists():
        return f"[ERROR: file not found: {path}]"

    text = path.read_text()
    prompts_dir = path.parent

    def _replacer(match: re.Match[str]) -> str:
        include_rel = match.group(1).strip()
        include_path = prompts_dir / include_rel
        # Also try from the prompts root (prompts/)
        if not include_path.exists():
            include_path = repo_root / "prompts" / include_rel
        return _resolve_includes(include_path, repo_root, depth + 1)

    return _INCLUDE_RE.sub(_replacer, text)


def _substitute_variables(text: str, variables: dict[str, str]) -> str:
    """Replace ``{{KEY}}`` placeholders with values from *variables*."""

    def _replacer(match: re.Match[str]) -> str:
        key = match.group(1)
        return variables.get(key, match.group(0))

    return _VAR_RE.sub(_replacer, text)


def build_variables_from_manifest(manifest: AttackManifest) -> dict[str, str]:
    """Map :class:`AttackManifest` fields to prompt template variable names."""
    variables: dict[str, str] = {
        "WEB_URL": manifest.target_url,
    }

    if manifest.login_instructions:
        variables["LOGIN_INSTRUCTIONS"] = manifest.login_instructions
    else:
        variables["LOGIN_INSTRUCTIONS"] = "No login instructions provided."

    if manifest.rules_avoid:
        variables["RULES_AVOID"] = "\n".join(f"- {r}" for r in manifest.rules_avoid)
    else:
        variables["RULES_AVOID"] = "None specified."

    if manifest.rules_focus:
        variables["RULES_FOCUS"] = "\n".join(f"- {r}" for r in manifest.rules_focus)
    else:
        variables["RULES_FOCUS"] = "None specified."

    # MCP server placeholder — we use our own tool definitions
    variables["MCP_SERVER"] = "Hellcat"

    # Login-instructions shared file variables
    if manifest.credentials:
        variables["user_instructions"] = (
            f"username: {manifest.credentials.get('username', '')}\n"
            f"password: {manifest.credentials.get('password', '')}"
        )
    else:
        variables["user_instructions"] = "No credentials provided."

    variables["totp_secret"] = ""

    return variables
