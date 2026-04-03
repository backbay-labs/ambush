"""
Kernel Initialization - Sets up the kernel in a repository.

Creates:
- .cyntra/ directory structure
- Default config.yaml
- Initial state files
"""

from __future__ import annotations

from pathlib import Path

import yaml
from rich.console import Console

console = Console()


def initialize_kernel(config_path: Path) -> None:
    """
    Initialize Cyntra in the current repository.

    Creates the .cyntra directory and default configuration.
    """
    # Determine repo root (parent of .cyntra)
    if config_path.name == "config.yaml":
        cyntra_dir = config_path.parent
    else:
        cyntra_dir = config_path / ".cyntra"
        config_path = cyntra_dir / "config.yaml"

    # Create directory structure
    cyntra_dir.mkdir(parents=True, exist_ok=True)
    (cyntra_dir / "logs").mkdir(exist_ok=True)
    (cyntra_dir / "archives").mkdir(exist_ok=True)
    (cyntra_dir / "state").mkdir(exist_ok=True)

    # Create workcells directory at repo root
    repo_root = cyntra_dir.parent
    (repo_root / ".workcells").mkdir(exist_ok=True)

    # Create default config if it doesn't exist
    if not config_path.exists():
        default_config = _create_default_config()
        with open(config_path, "w") as f:
            yaml.dump(default_config, f, default_flow_style=False, sort_keys=False)
        console.print(f"  Created [cyan]{config_path}[/cyan]")

    # Create .gitignore for workcells
    gitignore_path = repo_root / ".workcells" / ".gitignore"
    if not gitignore_path.exists():
        gitignore_path.write_text("# Ignore all workcells\n*\n!.gitignore\n")

    # Add to repo .gitignore if it exists
    repo_gitignore = repo_root / ".gitignore"
    if repo_gitignore.exists():
        content = repo_gitignore.read_text()
        additions = []
        if ".workcells/" not in content:
            additions.append(".workcells/")
        if ".cyntra/logs/" not in content:
            additions.append(".cyntra/logs/")
        if ".cyntra/archives/" not in content:
            additions.append(".cyntra/archives/")
        if ".cyntra/state/" not in content:
            additions.append(".cyntra/state/")

        if additions:
            with open(repo_gitignore, "a") as f:
                f.write("\n# Cyntra\n")
                for item in additions:
                    f.write(f"{item}\n")
            console.print(f"  Updated [cyan]{repo_gitignore}[/cyan]")

    console.print(f"\n[dim]Config:[/dim] {config_path}")
    console.print("[dim]Run:[/dim] cyntra run --once")


def _create_default_config() -> dict:
    """Create the default configuration dictionary."""
    return {
        "version": "1.0",
        "scheduling": {
            "max_concurrent_workcells": 3,
            "max_concurrent_tokens": 200_000,
            "starvation_threshold_hours": 4.0,
        },
        "toolchain_priority": ["codex", "claude", "opencode", "crush", "fab-world"],
        "toolchains": {
            "codex": {
                "enabled": True,
                "path": "codex",
                "default_model": "gpt-5.2",
                "timeout_minutes": 60,
                "max_tokens": 100_000,
                "config": {
                    "sandbox": "workspace-write",
                    "ask_for_approval": "never",
                    "model_reasoning_effort": "xhigh",
                },
            },
            "claude": {
                "enabled": True,
                "path": "claude",
                "default_model": "claude-opus-4-5-20251101",
                "timeout_minutes": 60,
                "max_tokens": 100_000,
                "config": {
                    "skip_permissions": True,
                    "output_format": "json",
                    "allowed_tools": ["Edit", "Write", "Bash", "Read"],
                    "ultrathink": True,
                },
            },
            "opencode": {
                "enabled": True,
                "path": "opencode",
                "default_model": "openai/gpt-5-nano",
                "timeout_minutes": 45,
                "max_tokens": 100_000,
            },
            "crush": {
                "enabled": True,
                "path": "crush",
                "timeout_minutes": 45,
                "max_tokens": 100_000,
                "config": {
                    "auto_approve": True,
                },
            },
            "fab-world": {
                "enabled": True,
                "timeout_minutes": 120,
            },
        },
        "routing": {
            "rules": [
                {"match": {"dk_tool_hint": "codex"}, "use": ["codex"]},
                {"match": {"dk_tool_hint": "claude"}, "use": ["claude"]},
                {"match": {"dk_tool_hint": "opencode"}, "use": ["opencode"]},
                {"match": {"dk_tool_hint": "crush"}, "use": ["crush"]},
                {"match": {"tags_any": ["asset:world"]}, "use": ["fab-world"]},
                {
                    "match": {"dk_risk": ["high", "critical"]},
                    "speculate": True,
                    "parallelism": 2,
                    "use": ["codex", "claude"],
                },
                {"match": {}, "use": ["claude"]},
            ],
            "fallbacks": {
                "codex": ["claude", "opencode"],
                "claude": ["codex", "opencode"],
                "opencode": ["claude"],
                "crush": ["opencode", "claude"],
            },
        },
        "control": {
            "enabled": True,
        },
        "gates": {
            "test_command": "cd kernel && pytest -q",
            "typecheck_command": "cd kernel && mypy src/cyntra",
            "lint_command": "cd kernel && ruff check .",
            "build_command": None,
            "timeout_seconds": 900,
            "retry_flaky": 1,
        },
        "speculation": {
            "enabled": True,
            "default_parallelism": 2,
            "max_parallelism": 3,
            "vote_threshold": 0.7,
            "auto_trigger_on_critical_path": True,
            "auto_trigger_risk_levels": ["high", "critical"],
        },
        "planner": {
            "mode": "off",
            "bundle_dir": None,
            "confidence_threshold": 0.2,
        },
    }
