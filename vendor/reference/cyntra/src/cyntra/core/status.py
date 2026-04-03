"""
Kernel Status - Display current kernel state.
"""

from __future__ import annotations

import json
from pathlib import Path

from rich.console import Console
from rich.table import Table

from cyntra.core.scheduler.routing import KernelConfig
from cyntra.core.state.manager import StateManager
from cyntra.core.workcell.manager import WorkcellManager

console = Console()


def show_status(
    config_path: Path,
    json_output: bool = False,
    verbose: bool = False,
) -> None:
    """Show the current kernel status."""
    config = KernelConfig.load(config_path)
    state_manager = StateManager(config)
    workcell_manager = WorkcellManager(config, config.repo_root)

    # Gather status
    graph = state_manager.load_beads_graph()
    active_workcells = workcell_manager.list_active()

    # Count issues by status
    status_counts: dict[str, int] = {}
    for issue in graph.issues:
        status_counts[issue.status] = status_counts.get(issue.status, 0) + 1

    status_data = {
        "issues": {
            "total": len(graph.issues),
            "by_status": status_counts,
        },
        "workcells": {
            "active": len(active_workcells),
            "max": config.max_concurrent_workcells,
        },
        "config": {
            "dry_run": config.dry_run,
            "watch_mode": config.watch_mode,
            "force_speculate": config.force_speculate,
        },
    }

    if json_output:
        console.print(json.dumps(status_data, indent=2))
        return

    # Rich output
    console.print("\n[bold blue]Cyntra Status[/bold blue]\n")

    # Issues table
    issues_table = Table(title="Issues")
    issues_table.add_column("Status", style="cyan")
    issues_table.add_column("Count", justify="right")

    for status, count in sorted(status_counts.items()):
        style = {
            "done": "green",
            "running": "yellow",
            "ready": "cyan",
            "blocked": "red",
            "escalated": "red bold",
        }.get(status, "")
        issues_table.add_row(status, str(count), style=style)

    console.print(issues_table)

    # Workcells
    console.print(
        f"\n[dim]Active Workcells:[/dim] {len(active_workcells)}/{config.max_concurrent_workcells}"
    )

    if verbose and active_workcells:
        wc_table = Table(title="Active Workcells")
        wc_table.add_column("ID")
        wc_table.add_column("Issue")
        wc_table.add_column("Created")

        for wc_path in active_workcells:
            info = workcell_manager.get_workcell_info(wc_path)
            if info:
                wc_table.add_row(
                    info.get("id", "?"),
                    f"#{info.get('issue_id', '?')}",
                    info.get("created", "?"),
                )

        console.print(wc_table)
