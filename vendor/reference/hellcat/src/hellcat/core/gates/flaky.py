"""
Flaky Tests - Track and manage flaky tests.
"""

from __future__ import annotations

import json
from pathlib import Path

from rich.console import Console
from rich.table import Table

from hellcat.core.scheduler.routing import KernelConfig

console = Console()


def list_flaky_tests(config_path: Path) -> None:
    """List known flaky tests."""
    config = KernelConfig.load(config_path)
    flaky_data = _load_flaky_data(config)

    if not flaky_data.get("tests"):
        console.print("[dim]No flaky tests recorded[/dim]")
        return

    table = Table(title="Flaky Tests")
    table.add_column("Test", style="cyan")
    table.add_column("Failures", justify="right")
    table.add_column("Last Seen")
    table.add_column("Status")

    for test_name, info in flaky_data["tests"].items():
        status = "[yellow]ignored[/yellow]" if info.get("ignored") else "[dim]tracked[/dim]"
        table.add_row(
            test_name[:60],
            str(info.get("failure_count", 0)),
            info.get("last_seen", "?")[:10],
            status,
        )

    console.print(table)


def ignore_flaky_test(config_path: Path, test_name: str) -> None:
    """Mark a test as ignored (won't fail quality gates)."""
    config = KernelConfig.load(config_path)
    flaky_data = _load_flaky_data(config)

    if "tests" not in flaky_data:
        flaky_data["tests"] = {}

    if test_name not in flaky_data["tests"]:
        flaky_data["tests"][test_name] = {
            "failure_count": 0,
            "last_seen": None,
        }

    flaky_data["tests"][test_name]["ignored"] = True

    _save_flaky_data(config, flaky_data)
    console.print(f"[green]✓[/green] Ignoring flaky test: {test_name}")


def clear_flaky_tests(config_path: Path) -> None:
    """Clear all flaky test data."""
    config = KernelConfig.load(config_path)
    _save_flaky_data(config, {"tests": {}})
    console.print("[green]✓[/green] Flaky test data cleared")


def record_flaky_test(config: KernelConfig, test_name: str) -> None:
    """Record a flaky test occurrence."""
    from datetime import datetime

    flaky_data = _load_flaky_data(config)

    if "tests" not in flaky_data:
        flaky_data["tests"] = {}

    if test_name not in flaky_data["tests"]:
        flaky_data["tests"][test_name] = {
            "failure_count": 0,
            "ignored": False,
        }

    flaky_data["tests"][test_name]["failure_count"] += 1
    flaky_data["tests"][test_name]["last_seen"] = datetime.utcnow().isoformat()

    _save_flaky_data(config, flaky_data)


def is_test_ignored(config: KernelConfig, test_name: str) -> bool:
    """Check if a test is in the ignore list."""
    flaky_data = _load_flaky_data(config)
    return flaky_data.get("tests", {}).get(test_name, {}).get("ignored", False)


def _load_flaky_data(config: KernelConfig) -> dict:
    """Load flaky test data."""
    flaky_file = config.state_dir / "flaky.json"

    if not flaky_file.exists():
        return {"tests": {}}

    try:
        return json.loads(flaky_file.read_text())
    except (json.JSONDecodeError, OSError):
        return {"tests": {}}


def _save_flaky_data(config: KernelConfig, data: dict) -> None:
    """Save flaky test data."""
    state_dir = config.state_dir
    state_dir.mkdir(parents=True, exist_ok=True)

    flaky_file = state_dir / "flaky.json"
    flaky_file.write_text(json.dumps(data, indent=2))
