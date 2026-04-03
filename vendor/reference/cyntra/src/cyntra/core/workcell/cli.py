"""
Workcell CLI - Commands for managing individual workcells.

This is typically run INSIDE a workcell to report progress and results.
"""

from __future__ import annotations

import json
from pathlib import Path

import click
from rich.console import Console

console = Console()


@click.group()
@click.version_option(version="0.1.0")
def main() -> None:
    """Workcell CLI - Run inside a workcell to manage execution."""
    pass


@main.command()
@click.option("--json", "as_json", is_flag=True, help="JSON output")
def info(as_json: bool) -> None:
    """Show current workcell information."""
    marker_path = Path(".workcell")

    if not marker_path.exists():
        console.print("[red]Error:[/red] Not inside a workcell")
        raise SystemExit(1)

    info_data = json.loads(marker_path.read_text())

    if as_json:
        console.print(json.dumps(info_data, indent=2))
    else:
        console.print("\n[bold cyan]Workcell Info[/bold cyan]\n")
        for key, value in info_data.items():
            console.print(f"  [dim]{key}:[/dim] {value}")
        console.print()


@main.command()
@click.argument("message")
def log(message: str) -> None:
    """Log a message to the workcell log."""
    from datetime import datetime

    logs_dir = Path("logs")
    logs_dir.mkdir(exist_ok=True)

    log_file = logs_dir / "workcell.log"

    timestamp = datetime.utcnow().isoformat()
    with open(log_file, "a") as f:
        f.write(f"[{timestamp}] {message}\n")

    console.print(f"[green]✓[/green] Logged: {message[:50]}...")


@main.command()
@click.argument("event_type")
@click.option("--data", type=str, help="JSON data for the event")
def event(event_type: str, data: str | None) -> None:
    """Emit a structured event."""
    from datetime import datetime

    logs_dir = Path("logs")
    logs_dir.mkdir(exist_ok=True)

    events_file = logs_dir / "events.jsonl"

    event_data = {
        "type": event_type,
        "timestamp": datetime.utcnow().isoformat(),
        "data": json.loads(data) if data else {},
    }

    with open(events_file, "a") as f:
        f.write(json.dumps(event_data) + "\n")

    console.print(f"[green]✓[/green] Event emitted: {event_type}")


@main.command()
@click.option("--status", required=True, type=click.Choice(["success", "partial", "failed"]))
@click.option("--confidence", type=float, default=0.8, help="Confidence score 0-1")
@click.option("--risk", type=click.Choice(["low", "medium", "high", "critical"]), default="medium")
def complete(status: str, confidence: float, risk: str) -> None:
    """Signal workcell completion and generate proof stub."""
    import subprocess
    from datetime import datetime

    # Get current commit
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        capture_output=True,
        text=True,
    )
    head_commit = result.stdout.strip() if result.returncode == 0 else "unknown"

    # Get diff stats
    result = subprocess.run(
        ["git", "diff", "--stat", "main...HEAD"],
        capture_output=True,
        text=True,
    )

    # Read workcell marker
    marker_path = Path(".workcell")
    marker = json.loads(marker_path.read_text()) if marker_path.exists() else {}

    # Generate proof stub
    proof = {
        "schema_version": "1.0.0",
        "workcell_id": marker.get("id", "unknown"),
        "issue_id": marker.get("issue_id", "unknown"),
        "status": status,
        "patch": {
            "head_commit": head_commit,
            "base_commit": marker.get("parent_commit", "unknown"),
            "files_changed": [],  # Would be populated by actual implementation
        },
        "verification": {
            "all_passed": status == "success",
            "gates": {},  # Would be populated by gate runner
        },
        "confidence": confidence,
        "risk_classification": risk,
        "metadata": {
            "completed_at": datetime.utcnow().isoformat(),
            "speculate_tag": marker.get("speculate_tag"),
        },
    }

    # Write proof
    proof_path = Path("proof.json")
    proof_path.write_text(json.dumps(proof, indent=2))

    console.print(f"[green]✓[/green] Workcell completed: {status}")
    console.print(f"  [dim]Proof written to:[/dim] {proof_path}")


@main.command()
@click.argument("gate", type=click.Choice(["test", "typecheck", "lint", "build", "all"]))
@click.option("--fix", is_flag=True, help="Auto-fix if possible")
def check(gate: str, fix: bool) -> None:
    """Run quality gate checks."""
    from cyntra.core.gates.runner import GateRunner

    runner = GateRunner.from_workcell()

    results = runner.run_all() if gate == "all" else {gate: runner.run_gate(gate, auto_fix=fix)}

    all_passed = all(r.get("passed", False) for r in results.values())

    for gate_name, result in results.items():
        status = "[green]✓[/green]" if result.get("passed") else "[red]✗[/red]"
        console.print(f"  {status} {gate_name}")

    if all_passed:
        console.print("\n[green]All gates passed[/green]")
    else:
        console.print("\n[red]Some gates failed[/red]")
        raise SystemExit(1)


if __name__ == "__main__":
    main()
