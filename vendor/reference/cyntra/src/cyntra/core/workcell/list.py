"""
Workcell List - Display active workcells.
"""

from __future__ import annotations

import json
from pathlib import Path

from rich.console import Console
from rich.table import Table

from cyntra.core.scheduler.routing import KernelConfig
from cyntra.core.workcell.manager import WorkcellManager

console = Console()


def list_workcells(
    config_path: Path,
    json_output: bool = False,
    include_archived: bool = False,
) -> None:
    """List active workcells."""
    config = KernelConfig.load(config_path)
    manager = WorkcellManager(config, config.repo_root)

    active = manager.list_active()

    if json_output:
        data = []
        for wc_path in active:
            info = manager.get_workcell_info(wc_path)
            if info:
                info["path"] = str(wc_path)
                data.append(info)
        console.print(json.dumps(data, indent=2))
        return

    if not active:
        console.print("[dim]No active workcells[/dim]")
        return

    table = Table(title="Active Workcells")
    table.add_column("ID", style="cyan")
    table.add_column("Issue")
    table.add_column("Created")
    table.add_column("Speculate")

    for wc_path in active:
        info = manager.get_workcell_info(wc_path)
        if info:
            table.add_row(
                info.get("id", "?"),
                f"#{info.get('issue_id', '?')}",
                info.get("created", "?"),
                info.get("speculate_tag", "-"),
            )

    console.print(table)

    if include_archived:
        _list_archived(config)


def _list_archived(config: KernelConfig) -> None:
    """List archived workcells."""
    archives_dir = config.archives_dir

    if not archives_dir.exists():
        return

    archives = list(archives_dir.iterdir())
    if not archives:
        return

    console.print(f"\n[dim]Archived: {len(archives)} workcells[/dim]")
