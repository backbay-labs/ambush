"""
E2B Auth Injection - Extract local CLI credentials and inject into E2B sandboxes.

Claude CLI uses macOS Keychain for OAuth credentials. The access token is
API-compatible (sk-ant-oat01-...) and can be set as ANTHROPIC_API_KEY.

Codex CLI stores OAuth tokens in ~/.codex/auth.json. The entire file must
be copied into the sandbox for the CLI to authenticate.
"""

from __future__ import annotations

import json
import logging
import platform
import subprocess
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Sentinel for "not extracted yet"
_NOT_EXTRACTED = object()


class CredentialBundle:
    """Extracted credentials ready for E2B sandbox injection."""

    def __init__(
        self,
        env_vars: dict[str, str] | None = None,
        files: dict[str, str] | None = None,
    ):
        # Environment variables to set in sandbox
        self.env_vars: dict[str, str] = env_vars or {}
        # Files to write in sandbox: {remote_path: content}
        self.files: dict[str, str] = files or {}

    def __repr__(self) -> str:
        env_keys = list(self.env_vars.keys())
        file_paths = list(self.files.keys())
        return f"CredentialBundle(env_vars={env_keys}, files={file_paths})"


def extract_claude_credentials() -> dict[str, str]:
    """Extract Claude CLI OAuth credentials from macOS Keychain.

    Returns a dict with CLAUDE_CODE_OAUTH_TOKEN if available, empty dict otherwise.
    The Claude CLI uses CLAUDE_CODE_OAUTH_TOKEN (not ANTHROPIC_API_KEY) for
    subscription-based OAuth auth. The token triggers the CLI's internal
    OAuth-to-API-key exchange flow.
    """
    if platform.system() != "Darwin":
        logger.debug("Claude keychain extraction only supported on macOS")
        return {}

    try:
        result = subprocess.run(
            ["security", "find-generic-password", "-s", "Claude Code-credentials", "-w"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode != 0:
            logger.warning("Claude keychain entry not found")
            return {}

        cred_data = json.loads(result.stdout.strip())
        oauth = cred_data.get("claudeAiOauth", {})
        access_token = oauth.get("accessToken", "")

        if not access_token:
            logger.warning("Claude keychain entry found but no accessToken")
            return {}

        logger.info("Extracted Claude OAuth token from Keychain (scope: %s)", oauth.get("scopes"))
        return {"CLAUDE_CODE_OAUTH_TOKEN": access_token}

    except subprocess.TimeoutExpired:
        logger.warning("Keychain access timed out")
        return {}
    except (json.JSONDecodeError, KeyError) as e:
        logger.warning("Failed to parse Claude keychain data: %s", e)
        return {}
    except Exception as e:
        logger.warning("Failed to extract Claude credentials: %s", e)
        return {}


def extract_codex_credentials() -> tuple[dict[str, str], dict[str, str]]:
    """Extract Codex CLI credentials from ~/.codex/auth.json.

    Returns (env_vars, files) where:
    - env_vars: any API keys found (e.g., OPENAI_API_KEY if set)
    - files: {remote_path: file_content} for auth.json to copy into sandbox
    """
    auth_path = Path.home() / ".codex" / "auth.json"

    if not auth_path.exists():
        logger.debug("Codex auth.json not found at %s", auth_path)
        return {}, {}

    try:
        content = auth_path.read_text()
        auth_data = json.loads(content)

        env_vars: dict[str, str] = {}
        files: dict[str, str] = {}

        # If OPENAI_API_KEY is stored directly, use it as env var
        api_key = auth_data.get("OPENAI_API_KEY")
        if api_key and isinstance(api_key, str):
            env_vars["OPENAI_API_KEY"] = api_key

        # Always copy the full auth.json for OAuth token auth
        tokens = auth_data.get("tokens", {})
        if tokens and isinstance(tokens, dict):
            files["/home/user/.codex/auth.json"] = content
            logger.info(
                "Extracted Codex auth.json (has tokens: %s)",
                list(tokens.keys()),
            )

        return env_vars, files

    except (json.JSONDecodeError, OSError) as e:
        logger.warning("Failed to read Codex auth.json: %s", e)
        return {}, {}


def build_credential_bundle(toolchains: list[str] | None = None) -> CredentialBundle:
    """Build a CredentialBundle for the requested toolchains.

    Args:
        toolchains: List of toolchain names to extract creds for.
                    If None, extracts all available credentials.

    Returns:
        CredentialBundle with env_vars and files ready for injection.
    """
    all_toolchains = toolchains is None
    env_vars: dict[str, str] = {}
    files: dict[str, str] = {}

    if all_toolchains or "claude" in (toolchains or []):
        claude_env = extract_claude_credentials()
        env_vars.update(claude_env)

    if all_toolchains or "codex" in (toolchains or []):
        codex_env, codex_files = extract_codex_credentials()
        env_vars.update(codex_env)
        files.update(codex_files)

    bundle = CredentialBundle(env_vars=env_vars, files=files)
    logger.info("Built credential bundle: %s", bundle)
    return bundle


async def inject_credentials_into_sandbox(
    sandbox: Any,
    bundle: CredentialBundle,
    run_id: str | None = None,
) -> None:
    """Inject credentials into a running E2B sandbox.

    Sets environment variables and writes files into the sandbox.

    Args:
        sandbox: E2B Sandbox instance
        bundle: Extracted credential bundle
        run_id: Optional run ID for logging
    """
    import asyncio

    loop = asyncio.get_event_loop()

    # Write files first (e.g., ~/.codex/auth.json)
    for remote_path, content in bundle.files.items():
        try:
            parent_dir = str(Path(remote_path).parent)
            await loop.run_in_executor(
                None,
                lambda d=parent_dir: sandbox.files.make_dir(d),
            )
            await loop.run_in_executor(
                None,
                lambda p=remote_path, c=content: sandbox.files.write(p, c),
            )
            logger.info("Wrote credential file to sandbox: %s", remote_path)
        except Exception as e:
            logger.error("Failed to write %s to sandbox: %s", remote_path, e)

    # Env vars are returned for the caller to merge into _sandbox_envs
    if bundle.env_vars:
        logger.info(
            "Credential env vars ready for injection: %s",
            list(bundle.env_vars.keys()),
        )
